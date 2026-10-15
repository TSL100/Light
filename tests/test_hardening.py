"""Hostile-input hardening and determinism/custody tests for step 9."""

import gzip
import io
import json
import sqlite3
import tarfile
import time

import pytest

from linuxdfir import cli, custody
from linuxdfir.config import load_config
from linuxdfir.detectors import timestomp_detection, unusual_suid
from linuxdfir.ingest import (
    MAX_LINE_LENGTH,
    Evidence,
    EvidenceError,
    UnsafeArchiveError,
)
from linuxdfir.report.sanitize import sanitize_cell
from linuxdfir.schema import Event, Finding, Severity

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def regular_member(name, data: bytes):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def build_tar(path, entries):
    with tarfile.open(path, "w:gz") as tar:
        for info, data in entries:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


MANIFEST = json.dumps(
    {
        "schema": "linuxdfir/collector-manifest/1",
        "hostname": "mini",
        "collection_time_utc": "2026-01-03T06:00:00Z",
        "timezone": {"name": None, "utc_offset_seconds": None},
        "files": [],
        "live_commands": [],
        "triage": [],
    }
).encode()


def ev(**kw):
    base = dict(
        timestamp_utc=None,
        host="h",
        user=None,
        source_artifact="/var/log/auth.log",
        event_type="auth_log",
        message="",
        evidence_path="/var/log/auth.log",
        line_or_offset=1,
        parser="auth_log",
    )
    base.update(kw)
    return Event(**base)


def finding(**kw):
    base = dict(
        id="f1",
        rule="r",
        severity=Severity.LOW,
        title="t",
        description="",
        mitre_ids=[],
        refs=[],
        count=1,
    )
    base.update(kw)
    return Finding(**base)


# ---------------------------------------------------------------------------
# path traversal / archive safety
# ---------------------------------------------------------------------------


def test_absolute_member_rejected(tmp_path):
    path = tmp_path / "abs.tar.gz"
    build_tar(path, [regular_member("/etc/passwd", b"x"), regular_member("manifest.json", MANIFEST)])
    with pytest.raises(UnsafeArchiveError):
        Evidence.open(path)


def test_parent_traversal_member_rejected(tmp_path):
    path = tmp_path / "dotdot.tar.gz"
    build_tar(path, [regular_member("../escape", b"x"), regular_member("manifest.json", MANIFEST)])
    with pytest.raises(UnsafeArchiveError):
        Evidence.open(path)


def test_control_char_member_rejected(tmp_path):
    path = tmp_path / "ctrl.tar.gz"
    build_tar(path, [regular_member("evidence/a\x1b[31mred", b"x"), regular_member("manifest.json", MANIFEST)])
    with pytest.raises(UnsafeArchiveError):
        Evidence.open(path)


def test_symlink_escape_rejected(tmp_path):
    path = tmp_path / "link.tar.gz"
    link_info = tarfile.TarInfo("evidence/link")
    link_info.type = tarfile.SYMTYPE
    link_info.linkname = "/etc/shadow"
    build_tar(
        path,
        [regular_member("manifest.json", MANIFEST), (link_info, None)],
    )
    with pytest.raises(UnsafeArchiveError):
        Evidence.open(path)


def test_hardlink_escape_rejected(tmp_path):
    path = tmp_path / "hard.tar.gz"
    link_info = tarfile.TarInfo("evidence/hard")
    link_info.type = tarfile.LNKTYPE
    link_info.linkname = "/etc/shadow"
    build_tar(
        path,
        [regular_member("manifest.json", MANIFEST), (link_info, None)],
    )
    with pytest.raises(UnsafeArchiveError):
        Evidence.open(path)


def test_member_count_cap(tmp_path, monkeypatch):
    monkeypatch.setattr("linuxdfir.ingest.MAX_MEMBER_COUNT", 3)
    path = tmp_path / "many.tar.gz"
    entries = [regular_member(f"f{i}", b"x") for i in range(10)]
    build_tar(path, entries)
    with pytest.raises(UnsafeArchiveError):
        Evidence.open(path)


def test_declared_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr("linuxdfir.ingest.MAX_MEMBER_BYTES", 10)
    path = tmp_path / "big.tar.gz"
    build_tar(path, [regular_member("manifest.json", MANIFEST), regular_member("big", b"x" * 100)])
    with pytest.raises(UnsafeArchiveError):
        Evidence.open(path)


# ---------------------------------------------------------------------------
# decompression bombs / huge lines
# ---------------------------------------------------------------------------


def test_gzip_bomb_member_rejected(tmp_path):
    """A small inner-gzip member that decompresses past the cap is rejected."""
    path = tmp_path / "bomb.tar.gz"
    zeros = b"\0" * (64 * 1024 * 1024)  # 64 MiB of zeros
    inner = gzip.compress(zeros)
    info = tarfile.TarInfo("evidence/zeros.log.gz")
    info.size = len(inner)
    build_tar(path, [regular_member("manifest.json", MANIFEST), (info, inner)])
    with Evidence.open(path) as evidence:
        with pytest.raises(EvidenceError):
            for _ in evidence.iter_lines("evidence/zeros.log.gz"):
                pass


def test_long_line_truncated(tmp_path):
    path = tmp_path / "longline.tar.gz"
    long = b"A" * (MAX_LINE_LENGTH * 3)
    build_tar(path, [regular_member("manifest.json", MANIFEST), regular_member("evidence/long.log", long)])
    with Evidence.open(path) as evidence:
        lines = list(evidence.iter_lines("evidence/long.log"))
    assert len(lines) == 1
    _lineno, text = lines[0]
    assert len(text) <= MAX_LINE_LENGTH


def test_manifest_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr("linuxdfir.ingest.MAX_MANIFEST_BYTES", 10)
    path = tmp_path / "bigmanifest.tar.gz"
    big = b"{" + b" " * 100 + b"}"
    build_tar(path, [regular_member("manifest.json", big)])
    with pytest.raises(EvidenceError):
        Evidence.open(path)


# ---------------------------------------------------------------------------
# formula-injection sanitisation (CSV / HTML / SQLite)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\t=1", "\r=1"],
)
def test_sanitize_cell_prefixes_formula_chars(raw):
    out = sanitize_cell(raw)
    assert out[0] == "'"


def test_neutralize_formula_leaves_normal_text():
    assert sanitize_cell("hello world") == "hello world"
    assert sanitize_cell("sshd[123]: Accepted password") == "sshd[123]: Accepted password"


def test_html_escapes_script_breakout():
    from linuxdfir.report.html import _json_blob

    blob = _json_blob({"rows": ["</script><script>alert(1)</script>"], "total": 1})
    assert "</script>" not in blob
    assert "\\u003c" in blob


def test_sqlite_parameter_is_not_injectable():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (a TEXT)")
    conn.execute("INSERT INTO t VALUES ('safe')")
    malicious = "'); DROP TABLE t;--"
    rows = conn.execute("SELECT a FROM t WHERE a = ?", (malicious,)).fetchall()
    assert rows == []
    # table still exists
    conn.execute("SELECT a FROM t")


# ---------------------------------------------------------------------------
# terminal escape sanitisation
# ---------------------------------------------------------------------------


def test_term_safe_strips_ansi_and_control():
    raw = "ok \x1b[31mred\x1b[0m \x07beep\x00null"
    out = cli.term_safe(raw)
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "\x00" not in out
    assert "ok red beepnull" == out


def test_term_safe_is_idempotent():
    once = cli.term_safe("a\x1b[1mb")
    assert cli.term_safe(once) == once


# ---------------------------------------------------------------------------
# regex safety (adversarial long input completes fast)
# ---------------------------------------------------------------------------


def test_redact_secrets_handles_long_line_quickly():
    from linuxdfir.redact import redact_secrets

    long_line = "password=hunter2 " + "x" * (MAX_LINE_LENGTH - 20)
    t0 = time.perf_counter()
    redact_secrets(long_line)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"redact took {elapsed:.3f}s on a max-length line"


def test_parse_syslog_prefix_long_line_quickly():
    from linuxdfir.timeutil import parse_syslog_prefix

    long_line = "Jan  1 00:00:00 " + "x" * (MAX_LINE_LENGTH - 16)
    t0 = time.perf_counter()
    parse_syslog_prefix(long_line)
    assert time.perf_counter() - t0 < 1.0


# ---------------------------------------------------------------------------
# timestomp: rotated-log / allowlist severity-lowering (provenance stated)
# ---------------------------------------------------------------------------


def _ts_event(path, mtime_iso, ctime_iso, host="h"):
    msg = (
        f"recent type=file mode=0o644 uid=0 gid=0 size=100 "
        f"mtime_utc={mtime_iso} ctime_utc={ctime_iso} path={path}"
    )
    return ev(event_type="recent_file", message=msg, host=host)


_OLD = "2025-01-01T00:00:00Z"
_NEW = "2026-01-15T00:00:00Z"


def test_timestomp_rotated_log_lowers_to_info():
    cfg = load_config()
    events = [
        _ts_event("/var/log/auth.log.1", _OLD, _NEW),
        _ts_event("/var/log/syslog-20260101", _OLD, _NEW),
        _ts_event("/var/log/auth.log.1.gz", _OLD, _NEW),
    ]
    findings = timestomp_detection.detect(events, config=cfg)
    assert findings, "rotated logs must still be reported, not skipped"
    assert all(f.severity is Severity.INFO for f in findings)
    for f in findings:
        assert "Provenance condition" in f.description
        assert "rotation suffix" in f.description
        assert "uid=" in f.description


def test_timestomp_allowlist_lowers_to_info():
    cfg = load_config()
    allowed = _ts_event("/usr/lib/wsl/WSL", _OLD, _NEW)
    not_allowed = _ts_event("/home/alice/evil.sh", _OLD, _NEW)
    findings = timestomp_detection.detect([allowed, not_allowed], config=cfg)
    allowed_finding = next(f for f in findings if "/usr/lib/wsl/WSL" in f.title)
    other_finding = next(f for f in findings if "/home/alice/evil.sh" in f.title)
    assert allowed_finding.severity is Severity.INFO
    assert "provenance prefix '/usr/lib/wsl/'" in allowed_finding.description
    assert "uid=0" in allowed_finding.description
    assert other_finding.severity is Severity.LOW


def test_timestomp_active_log_still_alerts():
    cfg = load_config()
    findings = timestomp_detection.detect([_ts_event("/var/log/auth.log", _OLD, _NEW)], config=cfg)
    assert findings, "active auth.log timestomp should still alert"
    assert findings[0].severity in (Severity.LOW, Severity.INFO)


# ---------------------------------------------------------------------------
# offensive_tools: tool/tunnel directory detection (INFO/LOW, never skipped)
# ---------------------------------------------------------------------------


def _fs_event(path, mode="0o644", type_="file"):
    msg = (
        f"recent type={type_} mode={mode} uid=0 gid=0 size=100 "
        f"mtime_utc={_NEW} ctime_utc={_NEW} path={path}"
    )
    return ev(event_type="recent_file", message=msg)


def test_offensive_tool_directory_reported():
    from linuxdfir.detectors import offensive_tools

    cfg = load_config()
    findings = offensive_tools.detect(
        [_fs_event("/root/evilgophish-1/config.yml"), _fs_event("/root/evilginx", type_="dir")],
        config=cfg,
    )
    tools = " ".join(f.title for f in findings)
    assert "evilgophish" in tools
    assert "evilginx" in tools
    assert all(f.severity in (Severity.INFO, Severity.LOW) for f in findings)


def test_offensive_tool_executable_is_low():
    from linuxdfir.detectors import offensive_tools

    cfg = load_config()
    findings = offensive_tools.detect(
        [_fs_event("/opt/cloudflared", mode="0o755")], config=cfg
    )
    assert findings and findings[0].severity is Severity.LOW
    assert "Tunnel/proxy tooling" in findings[0].title


def test_offensive_tool_not_suppressed_by_timestomp_allowlist():
    from linuxdfir.detectors import offensive_tools

    cfg = load_config()
    findings = offensive_tools.detect(
        [_fs_event("/var/cache/apt/evilginx/setup")], config=cfg
    )
    assert findings, "timestomp provenance prefix must not suppress tool detection"


def test_offensive_tool_hidden_dot_directory_reported():
    """A hidden tool directory such as /root/.evilginx must still match."""
    from linuxdfir.detectors import offensive_tools

    cfg = load_config()
    findings = offensive_tools.detect(
        [_fs_event("/root/.evilginx/config.yml"), _fs_event("/root/.evilgophish/run.sh")],
        config=cfg,
    )
    tools = " ".join(f.title for f in findings)
    assert "evilginx" in tools
    assert "evilgophish" in tools
    assert all(f.severity in (Severity.INFO, Severity.LOW) for f in findings)


# ---------------------------------------------------------------------------
# scan-secrets: collector output must not leak secret material
# ---------------------------------------------------------------------------


def test_scan_secrets_detects_and_never_echoes(tmp_path):
    from linuxdfir.cli import main

    secret = "hunter2SuperSecretValue"
    (tmp_path / "history.txt").write_text(
        f"echo password={secret}\nsshpass -p {secret} ssh root@10.0.0.1\n", encoding="utf-8"
    )
    (tmp_path / "clean.txt").write_text("echo hello\n", encoding="utf-8")
    out = tmp_path / "out"
    rc = main(["scan-secrets", str(tmp_path), "-o", str(out)])
    assert rc == 0
    report = json.loads((out / "scan_secrets.json").read_text(encoding="utf-8"))
    assert report["files_with_hits"] >= 1
    assert report["total_hits"] >= 2
    # The raw secret must never appear in any report field.
    blob = json.dumps(report)
    assert secret not in blob
    assert "[REDACTED-" in blob


def test_scan_secrets_clean_run_is_clean(tmp_path):
    """A correctly redacted run (markers only) must scan clean."""
    from linuxdfir.cli import main

    (tmp_path / "events.txt").write_text(
        "echo [REDACTED-PASSWORD:ab12cd34] ssh\n", encoding="utf-8"
    )
    rc = main(["scan-secrets", str(tmp_path)])
    assert rc == 0


# ---------------------------------------------------------------------------
# unusual_suid: type=dir skip + standard binaries allowlisted
# ---------------------------------------------------------------------------


def _suid_event(path, type_="file"):
    msg = (
        f"suid_sgid type={type_} mode=0o4755 uid=0 gid=0 size=200000 "
        f"mtime_utc=2026-01-01T00:00:00Z flags=- path={path}"
    )
    return ev(event_type="suid_sgid_file", message=msg)


def test_unusual_suid_skips_dirs():
    findings = unusual_suid.detect([_suid_event("/var/log/journal", type_="dir")])
    assert findings == []


def test_unusual_suid_allows_standard_binaries():
    cfg = load_config()
    for path in (
        "/usr/bin/chage",
        "/usr/bin/expiry",
        "/usr/sbin/unix_chkpwd",
        "/usr/sbin/pam_extrausers_chkpwd",
        "/usr/lib/polkit-1/polkit-agent-helper-1",
    ):
        findings = unusual_suid.detect([_suid_event(path)], config=cfg)
        assert findings == [], f"{path} should be allowlisted"


def test_unusual_suid_flags_real_binary():
    findings = unusual_suid.detect([_suid_event("/usr/local/bin/totally-new")])
    assert findings


# ---------------------------------------------------------------------------
# determinism: two runs -> byte-identical findings.json
# ---------------------------------------------------------------------------


def test_findings_json_deterministic(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    out1 = tmp_path / "det1"
    out2 = tmp_path / "det2"
    cli.main(["run", str(archive), "-o", str(out1)])
    cli.main(["run", str(archive), "-o", str(out2)])
    a = (out1 / "findings.json").read_bytes()
    b = (out2 / "findings.json").read_bytes()
    assert a == b


def test_event_file_is_reiterable(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    out = tmp_path / "reiter"
    cli.main(["parse", str(archive), "-o", str(out)])
    stream = cli._load_events(out)
    first = list(stream)
    second = list(stream)
    assert len(first) == len(second)
    assert len(first) > 0


# ---------------------------------------------------------------------------
# loopback listener is LOW
# ---------------------------------------------------------------------------


def _ss_event(local, process="proc"):
    msg = f"ss LISTEN local={local} remote=0.0.0.0:0 users:((\"{process}\",pid=1,fd=3))"
    return ev(event_type="ss_socket", message=msg)


def test_loopback_listener_is_low():
    from linuxdfir.detectors import suspicious_processes

    cfg = load_config()
    findings = suspicious_processes.detect([_ss_event("127.0.0.1:4444")], config=cfg)
    listener = [f for f in findings if f.title.startswith("Unexpected listener")]
    assert listener and listener[0].severity is Severity.LOW


def test_public_listener_still_medium():
    from linuxdfir.detectors import suspicious_processes

    cfg = load_config()
    findings = suspicious_processes.detect([_ss_event("0.0.0.0:8080")], config=cfg)
    listener = [f for f in findings if f.title.startswith("Unexpected listener")]
    assert listener and listener[0].severity is Severity.MEDIUM


# ---------------------------------------------------------------------------
# chain of custody: analysis_log.json
# ---------------------------------------------------------------------------


def test_run_writes_analysis_log(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    out = tmp_path / "custody"
    rc = cli.main(["run", str(archive), "-o", str(out)])
    assert rc == 0
    log_path = out / "analysis_log.json"
    assert log_path.is_file()
    data = json.loads(log_path.read_text(encoding="utf-8"))
    assert data["schema"] == "linuxdfir.analysis_log/1"
    assert data["evidence_modified"] is False
    assert data["input"]["sha256"]
    assert data["input"]["kind"] == "archive"
    assert data["config"]["sha256"]
    assert data["tool"]["name"] == "linuxdfir"
    assert isinstance(data["parsers"]["count"], int)
    assert data["detectors"]["count"] > 0


def test_parse_writes_analysis_log(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    out = tmp_path / "custody_parse"
    rc = cli.main(["parse", str(archive), "-o", str(out)])
    assert rc == 0
    data = json.loads((out / "analysis_log.json").read_text(encoding="utf-8"))
    assert data["schema"] == "linuxdfir.analysis_log/1"


def test_analysis_log_config_hash_stable(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    out = tmp_path / "hash1"
    cli.main(["run", str(archive), "-o", str(out)])
    cfg = load_config()
    expected = custody.config_sha256(cfg)
    data = json.loads((out / "analysis_log.json").read_text(encoding="utf-8"))
    assert data["config"]["sha256"] == expected


def test_evidence_unchanged_by_analysis(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    before = custody.sha256_file(archive)
    out = tmp_path / "unchanged"
    cli.main(["run", str(archive), "-o", str(out)])
    after = custody.sha256_file(archive)
    assert before == after


def test_analysis_log_command_line_recorded(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    out = tmp_path / "cmdline"
    argv = ["run", str(archive), "-o", str(out)]
    cli.main(argv)
    data = json.loads((out / "analysis_log.json").read_text(encoding="utf-8"))
    assert data["command_line"][0] == "linuxdfir"
    assert str(archive) in data["command_line"]


# ---------------------------------------------------------------------------
# item 1: large-run write failure -> non-zero exit, no success output
# ---------------------------------------------------------------------------


def test_detect_write_failure_exits_nonzero_no_success(monkeypatch, capsys, generated, tmp_path):
    from linuxdfir.report import json_report

    archive = generated["results"]["infected"]["archive"]
    events_dir = tmp_path / "ev"
    cli.main(["parse", str(archive), "-o", str(events_dir)])
    events_file = events_dir / "events.jsonl"

    def boom(findings, path):
        raise json_report.WriteError("simulated disk failure")

    monkeypatch.setattr(json_report, "write_findings", boom)
    rc = cli.main(["detect", str(events_file), "-o", str(tmp_path / "out")])
    captured = capsys.readouterr()
    assert rc != 0, "write failure must produce a non-zero exit code"
    assert "findings         :" not in captured.out, "must not print success summary on failure"
    assert "iocs             :" not in captured.out, "must not print iocs summary on failure"
    assert "detect failed" in captured.err.lower()


def test_write_findings_is_atomic_verified(tmp_path):
    from linuxdfir.report import json_report

    target = tmp_path / "findings.json"
    json_report.write_findings([finding()], target)
    assert target.is_file()
    assert not target.with_name("findings.json.tmp").exists()
    parsed = json.loads(target.read_text(encoding="utf-8"))
    assert isinstance(parsed, list)


def test_atomic_write_rejects_bad_json(tmp_path):
    from linuxdfir.report import json_report

    with pytest.raises(json_report.WriteError):
        json_report.atomic_write_text(tmp_path / "bad.json", "{not valid json", verify_json=True)

