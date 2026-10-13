import base64
import csv
import hashlib
import json
import re
import tarfile

from conftest import flip_first_byte, repack_variant

from linuxdfir import cli
from linuxdfir.report import csv_report, html, json_report
from linuxdfir.report.sanitize import neutralize_formula, redact_shadow_hashes, sanitize_cell
from linuxdfir.schema import Finding, Ref, Severity

EVIL_USER = "<script>alert(1)</script>"
EVIL_CMD = '"><img src=x onerror=alert(2)>'
SHADOW_LINE = "root:$6$rounds=5000$abcdefgh$ijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789ab:20000:0:99999:7:::"


def write_report_fixture(root, *, shadow=False):
    message = f"Failed password for {EVIL_USER} from 203.0.113.9 port 5"
    raw = f"Jan  2 03:10:07 web01 sshd[1]: curl {EVIL_CMD}"
    if shadow:
        message += f" hash {SHADOW_LINE}"
        raw += f" {SHADOW_LINE}"
    events = [
        {
            "timestamp_utc": "2026-01-02T01:10:07+00:00",
            "timestamp_quality": "inferred_year",
            "host": "web01",
            "user": EVIL_USER,
            "source_artifact": "auth_log",
            "event_type": "ssh_failed_login",
            "message": message,
            "evidence_path": "/var/log/auth.log",
            "line_or_offset": 9,
            "raw": raw,
            "tags": ["ssh"],
            "mitre_ids": [],
            "confidence": 1.0,
            "parser": "auth_log",
            "repeat_count": 1,
        },
        {
            "timestamp_utc": "2026-01-02T01:12:44+00:00",
            "timestamp_quality": "inferred_year",
            "host": "web01",
            "user": "root",
            "source_artifact": "auth_log",
            "event_type": "ssh_accepted_login",
            "message": "Accepted password for root from 203.0.113.9 port 51400",
            "evidence_path": "/var/log/auth.log",
            "line_or_offset": 57,
            "raw": "Jan  2 03:12:44 web01 sshd[2]: Accepted password for root from 203.0.113.9 port 51400 ssh2",
            "tags": ["ssh"],
            "mitre_ids": [],
            "confidence": 1.0,
            "parser": "auth_log",
            "repeat_count": 1,
        },
    ]
    root.mkdir(parents=True, exist_ok=True)
    (root / "events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    findings = [
        {
            "id": "f" * 16,
            "rule": "ssh_bruteforce_then_success",
            "severity": "critical",
            "title": f"evil title {EVIL_USER}",
            "description": f"run {EVIL_CMD}",
            "mitre_ids": ["T1110.001", "T1078"],
            "first_seen": "2026-01-02T01:10:07+00:00",
            "last_seen": "2026-01-02T01:12:44+00:00",
            "count": 48,
            "refs": [{"evidence_path": "/var/log/auth.log", "line_or_offset": 9}],
        }
    ]
    (root / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    (root / "timeline_stats.json").write_text(
        json.dumps(
            {
                "total": 2,
                "dated": 2,
                "undated": 0,
                "suspicious_time": 0,
                "per_artifact": {"auth_log": 2},
                "per_day": {"2026-01-02": 2},
                "per_event_type": {"ssh_failed_login": 1, "ssh_accepted_login": 1},
            }
        ),
        encoding="utf-8",
    )
    (root / "verify_report.json").write_text(
        json.dumps(
            {
                "integrity_ok": True,
                "counts": {"ok": 2, "mismatch": 0, "missing": 0, "extra": 0, "metadata_only": 0},
                "sidecar": {"status": "ok", "actual": "ab" * 32},
                "mismatch": [],
                "missing": [],
                "extra": [],
            }
        ),
        encoding="utf-8",
    )
    (root / "parse_stats.json").write_text("[]", encoding="utf-8")
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "hostname": "web01",
                "collection_time_utc": "2026-01-03T06:00:00Z",
                "collector": {"version": "1.0.0"},
                "timezone": {"name": "Africa/Cairo", "utc_offset_str": "+0200"},
                "environment": {"wsl": False, "container": None, "platform": "Linux-test"},
                "skipped": [
                    {
                        "original_path": "/var/log/lastlog",
                        "category": "auth",
                        "status": "not_present",
                        "reason": "not present",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return root


def test_run_infected_end_to_end(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    out = tmp_path / "run"
    assert cli.main(["run", str(archive), "-o", str(out)]) == 0
    for name in ("report.html", "findings.csv", "findings.json", "events.jsonl", "timeline.csv", "timeline.db"):
        assert (out / name).is_file(), name
    page = (out / "report.html").read_text(encoding="utf-8")
    assert "SSH brute force then success from 203.0.113.9" in page
    assert "/var/log/auth.log" in page
    assert "Password Guessing" in page and "T1110.001" in page
    assert "Credential Access" in page
    assert "Evidence integrity: OK" in page


def test_run_clean_has_no_high_or_critical(generated, tmp_path):
    archive = generated["results"]["clean"]["archive"]
    out = tmp_path / "run"
    assert cli.main(["run", str(archive), "-o", str(out)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert all(f["severity"] in ("info", "low", "medium") for f in findings)
    page = (out / "report.html").read_text(encoding="utf-8")
    assert "No findings." in page
    assert '<span class="sev sev-critical">' not in page
    assert '<span class="sev sev-high">' not in page


def test_run_tampered_exit_code_2(generated, tmp_path):
    src = generated["results"]["infected"]["archive"]
    with tarfile.open(src, "r:gz") as tar:
        original = tar.extractfile("evidence/etc/hosts").read()
    dst = repack_variant(
        src, tmp_path / "tampered.tar.gz", modify={"evidence/etc/hosts": flip_first_byte(original)}
    )
    out = tmp_path / "run"
    assert cli.main(["run", str(dst), "-o", str(out)]) == 2
    assert "FAILED" in (out / "report.html").read_text(encoding="utf-8")


def test_report_standalone_and_missing_findings(generated, tmp_path):
    archive = generated["results"]["clean"]["archive"]
    out = tmp_path / "run"
    assert cli.main(["run", str(archive), "-o", str(out)]) == 0
    assert cli.main(["report", str(out)]) == 0
    assert (out / "report.html").is_file() and (out / "findings.csv").is_file()
    assert cli.main(["report", str(tmp_path / "empty")]) == 1


def test_xss_payloads_escaped_and_inert(tmp_path):
    root = write_report_fixture(tmp_path / "xss")
    target = html.build_report(root)
    page = target.read_text(encoding="utf-8")
    assert EVIL_USER not in page
    assert EVIL_CMD not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert page.count("<script>") == 1
    assert "innerHTML" not in page
    assert "http://" not in page and "https://" not in page
    assert 'src="' not in page
    assert all(href.startswith("#") for href in re.findall(r'href="([^"]*)"', page))
    assert "Content-Security-Policy" in page
    csp = re.search(r"Content-Security-Policy' content='(.*?)'>", page).group(1)
    script_hash = re.search(r"script-src 'sha256-([^']+)'", csp).group(1)
    code = re.search(r"<script>(.*?)</script>", page, re.DOTALL).group(1)
    digest = base64.b64encode(hashlib.sha256(code.encode("utf-8")).digest()).decode("ascii")
    assert digest == script_hash
    style_hash = re.search(r"style-src 'sha256-([^']+)'", csp).group(1)
    css = re.search(r"<style>(.*?)</style>", page, re.DOTALL).group(1)
    assert base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode("ascii") == style_hash


def test_shadow_hashes_redacted(tmp_path):
    root = write_report_fixture(tmp_path / "shadow", shadow=True)
    target = html.build_report(root)
    page = target.read_text(encoding="utf-8")
    assert "$6$rounds=5000$abcdefgh" not in page
    assert "ijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789ab" not in page
    assert "[HASH-REDACTED]" in page
    finding = Finding(
        id="x",
        rule="r",
        severity=Severity.HIGH,
        title="t",
        description=f"leak {SHADOW_LINE}",
        refs=[Ref("/etc/shadow", 1)],
    )
    csv_report.write_csv([finding], root / "f.csv")
    text = (root / "f.csv").read_text(encoding="utf-8")
    assert "$6$rounds=5000" not in text and "[HASH-REDACTED]" in text
    json_report.write_findings([finding], root / "f.json")
    assert "$6$rounds=5000" not in (root / "f.json").read_text(encoding="utf-8")


def test_redaction_leaves_normal_dollar_text():
    assert redact_shadow_hashes("cost is $5 and $HOME is set") == "cost is $5 and $HOME is set"
    assert redact_shadow_hashes(None) is None


def test_csv_formula_neutralized(tmp_path):
    findings = [
        Finding(
            id=f"id{i}",
            rule="r",
            severity=Severity.MEDIUM,
            title=title,
            description="d",
            refs=[Ref("/p", 1)],
        )
        for i, title in enumerate(["=cmd|' /c calc'!A", "+evil", "-2+3", "@mal", "plain title"])
    ]
    target = csv_report.write_csv(findings, tmp_path / "f.csv")
    rows = list(csv.reader(open(target, encoding="utf-8")))
    assert rows[0][0] == "id"
    assert [row[3] for row in rows[1:]] == ["'=cmd|' /c calc'!A", "'+evil", "'-2+3", "'@mal", "plain title"]
    assert neutralize_formula(42) == 42
    assert sanitize_cell(None) is None


def test_csv_refs_cell_and_mitre():
    finding = Finding(
        id="x",
        rule="r",
        severity=Severity.LOW,
        title="t",
        description="d",
        mitre_ids=["T1110.001"],
        refs=[Ref("/a", 1), Ref("/b", None)],
    )
    row = csv_report.finding_to_row(finding)
    assert row[2] == "low" and row[5] == "T1110.001" and row[9] == "/a:1; /b:"


def test_mitre_matrix_and_guidance_content(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    out = tmp_path / "run"
    assert cli.main(["run", str(archive), "-o", str(out)]) == 0
    page = (out / "report.html").read_text(encoding="utf-8")
    assert "TA0006" in page and "Valid Accounts" in page
    assert "Why it matters" in page and "Recommended next steps" in page
    assert "context" in page and "timeline.csv" in page


def test_json_report_writer(tmp_path):
    finding = Finding(id="x", rule="r", severity="info", title="t", description="d")
    target = json_report.write_findings([finding], tmp_path / "f.json")
    assert json.loads(target.read_text(encoding="utf-8"))[0]["severity"] == "info"
