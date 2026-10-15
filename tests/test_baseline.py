"""Clean-baseline drift: profiles, add/remove diffs, CLI wiring.

Baseline comparison needs no optional dependencies: every test here uses
plain Event objects, events.jsonl fixtures, or mini evidence folders.
"""

from __future__ import annotations

import json

from conftest import make_mini_evidence

from linuxdfir import cli
from linuxdfir.baseline import (
    RULES,
    diff_profiles,
    extract_profile,
    scan_with_baseline,
)
from linuxdfir.schema import Event, Severity


def _event(**kw) -> Event:
    defaults = dict(
        timestamp_utc=None,
        host="test",
        user=None,
        source_artifact="test",
        event_type="test",
        message="",
        evidence_path="/test",
        line_or_offset=1,
    )
    defaults.update(kw)
    return Event(**defaults)


def _user(name):
    return _event(
        event_type="user_account",
        user=name,
        message=f"account {name}: uid=1000 gid=1000 shell=/bin/bash home=/home/{name} [interactive-shell]",
        evidence_path="/etc/passwd",
    )


def _suid(path):
    return _event(
        event_type="suid_sgid_file",
        message=f"suid mode=4755 uid=0 gid=0 size=100 mtime_utc=2026-01-01T00:00:00Z flags=suid path={path}",
        evidence_path="triage/suid_sgid.txt",
    )


def _cron(schedule, user, command):
    return _event(
        event_type="cron_job",
        user=user,
        message=f"cron [{schedule}] {user}: {command}",
        evidence_path="/etc/cron.d/job",
    )


def _unit(path):
    return _event(
        event_type="systemd_unit",
        message="unit evil.service: evil (user=root)",
        evidence_path=path,
    )


def _package(name):
    return _event(
        event_type="package_install",
        message=f"package install {name} 1.0",
        evidence_path="/var/log/dpkg.log",
    )


def _listener(netid, local, proc):
    return _event(
        event_type="ss_socket",
        message=f"ss LISTEN netid={netid} local={local} peer=0.0.0.0:* process={proc}",
        evidence_path="live/ss_tulpn.txt",
    )


def _diff(target, baseline, config=None):
    return diff_profiles(
        extract_profile(target),
        extract_profile(baseline),
        config or {"baseline": {}},
        target_label="target",
        baseline_label="baseline",
    )


def test_users_added_and_removed():
    target = [_user("root"), _user("alice"), _user("evil")]
    baseline = [_user("root"), _user("alice"), _user("oldsvc")]
    findings, stats = _diff(target, baseline)
    by_title = {f.title: f for f in findings}
    added = next(f for f in findings if "added" in f.title and f.rule == "baseline_users")
    removed = next(f for f in findings if "removed" in f.title and f.rule == "baseline_users")
    assert "evil" in added.title
    assert added.severity == Severity.HIGH
    assert added.count == 1
    assert added.mitre_ids == ["T1136"]
    assert "oldsvc" in removed.title
    assert removed.severity == Severity.MEDIUM
    assert stats["categories"]["baseline_users"]["compared"] is True
    assert by_title  # titles are unique per direction


def test_suid_cron_systemd_packages_listeners_added():
    target = [
        _suid("/usr/bin/sudo"),
        _suid("/tmp/evil"),
        _cron("* * * * *", "root", "/tmp/x.sh"),
        _cron("0 3 * * *", "root", "/usr/bin/backup"),
        _unit("/etc/systemd/system/sshd.service"),
        _unit("/etc/systemd/system/evil.service"),
        _package("openssh-server"),
        _package("netcat-traditional"),
        _listener("tcp", "0.0.0.0:22", "sshd/100"),
        _listener("tcp", "0.0.0.0:4444", "evil/999"),
    ]
    baseline = [
        _suid("/usr/bin/sudo"),
        _cron("0 3 * * *", "root", "/usr/bin/backup"),
        _unit("/etc/systemd/system/sshd.service"),
        _package("openssh-server"),
        _listener("tcp", "0.0.0.0:22", "sshd/100"),
    ]
    findings, stats = _diff(target, baseline)
    assert stats["compared"] == 5
    hits = {f.rule: f for f in findings}
    assert "/tmp/evil" in hits["baseline_suid"].title
    assert "/tmp/x.sh" in hits["baseline_cron"].title
    assert "evil.service" in hits["baseline_systemd"].title
    assert "netcat-traditional" in hits["baseline_packages"].title
    assert "0.0.0.0:4444" in hits["baseline_listeners"].title
    assert hits["baseline_suid"].mitre_ids == ["T1548.001"]
    assert hits["baseline_cron"].mitre_ids == ["T1053.003"]
    assert hits["baseline_systemd"].mitre_ids == ["T1543.002"]
    assert hits["baseline_packages"].mitre_ids == ["T1588.002"]
    assert hits["baseline_listeners"].mitre_ids == ["T1059.004"]


def test_listener_pid_change_is_not_drift():
    target = [_listener("tcp", "0.0.0.0:22", "sshd/200")]
    baseline = [_listener("tcp", "0.0.0.0:22", "sshd/100")]
    findings, stats = _diff(target, baseline)
    assert findings == []
    assert stats["categories"]["baseline_listeners"]["compared"] is True


def test_listener_process_change_is_drift():
    target = [_listener("tcp", "0.0.0.0:22", "evil/200")]
    baseline = [_listener("tcp", "0.0.0.0:22", "sshd/100")]
    findings, _ = _diff(target, baseline)
    assert len(findings) == 2  # one added, one removed
    assert {f.severity for f in findings} == {Severity.HIGH, Severity.MEDIUM}


def test_identical_profiles_have_no_findings():
    events = [_user("root"), _suid("/usr/bin/sudo"), _package("vim")]
    findings, stats = _diff(list(events), list(events))
    assert findings == []
    compared = [r for r, e in stats["categories"].items() if e["compared"]]
    assert set(compared) == {"baseline_users", "baseline_suid", "baseline_packages"}


def test_no_coverage_side_is_skipped_not_reported():
    target = [_listener("tcp", "0.0.0.0:4444", "evil/1"), _user("root")]
    baseline = [_user("root")]  # e.g. collected with --skip-live
    findings, stats = _diff(target, baseline)
    listeners = stats["categories"]["baseline_listeners"]
    assert listeners["compared"] is False
    assert listeners["skipped_no_coverage"] == ["baseline"]
    assert all(f.rule != "baseline_listeners" for f in findings)
    # users compare normally
    assert stats["categories"]["baseline_users"]["compared"] is True


def test_unparseable_entries_are_ignored():
    target = [
        _event(event_type="suid_sgid_file", message="garbage without path"),
        _suid("/usr/bin/sudo"),
    ]
    baseline = [_suid("/usr/bin/sudo")]
    findings, stats = _diff(target, baseline)
    assert findings == []
    assert stats["categories"]["baseline_suid"]["compared"] is True


def test_non_listen_sockets_ignored():
    target = [
        _event(
            event_type="ss_socket",
            message="ss ESTAB netid=tcp local=10.0.0.1:22 peer=10.0.0.2:5000 process=sshd/1",
        )
    ]
    baseline = [
        _event(
            event_type="ss_socket",
            message="ss LISTEN netid=tcp local=0.0.0.0:22 peer=0.0.0.0:* process=sshd/1",
        )
    ]
    findings, stats = _diff(target, baseline)
    assert findings == []
    assert stats["categories"]["baseline_listeners"]["compared"] is False


def test_config_severities():
    target = [_user("root"), _user("evil")]
    baseline = [_user("root")]
    findings, _ = _diff(target, baseline, {"baseline": {"severity_added": "critical"}})
    assert findings[0].severity == Severity.CRITICAL
    findings, _ = _diff(baseline, target, {"baseline": {"severity_removed": "low"}})
    assert findings[0].severity == Severity.LOW


def test_scan_with_baseline_labels_and_rules():
    findings, stats = scan_with_baseline(
        [_user("root")], [_user("root")],
        {"baseline": {}},
        target_label="web01", baseline_label="golden",
    )
    assert stats["status"] == "ok"
    assert stats["target"] == "web01"
    assert stats["baseline"] == "golden"
    assert findings == []
    assert set(stats["categories"]) == set(RULES)


def _write_events_jsonl(path, events):
    path.write_text(
        "\n".join(json.dumps(e.to_dict()) for e in events) + "\n", encoding="utf-8"
    )


def test_scan_baseline_cli_with_events(tmp_path):
    target_dir = tmp_path / "target-events"
    target_dir.mkdir()
    _write_events_jsonl(target_dir / "events.jsonl", [_user("root"), _user("evil")])
    base_dir = tmp_path / "base-events"
    base_dir.mkdir()
    _write_events_jsonl(base_dir / "events.jsonl", [_user("root")])
    out = tmp_path / "out"
    assert cli.main(["scan-baseline", str(target_dir), "--baseline", str(base_dir), "-o", str(out)]) == 0
    report = json.loads((out / "baseline_findings.json").read_text(encoding="utf-8"))
    assert report["status"] == "ok"
    assert len(report["findings"]) == 1
    hit = report["findings"][0]
    assert hit["rule"] == "baseline_users"
    assert "evil" in hit["title"]


def test_scan_baseline_cli_prints_summary(tmp_path, capsys):
    target_dir = tmp_path / "t"
    target_dir.mkdir()
    _write_events_jsonl(target_dir / "events.jsonl", [_user("root"), _user("evil")])
    base_dir = tmp_path / "b"
    base_dir.mkdir()
    _write_events_jsonl(base_dir / "events.jsonl", [_user("root")])
    assert cli.main(["scan-baseline", str(target_dir), "--baseline", str(base_dir)]) == 0
    printed = capsys.readouterr().out
    assert "baseline_users" in printed
    assert "evil" in printed


def test_scan_baseline_cli_missing_baseline_errors(tmp_path, capsys):
    target_dir = tmp_path / "t"
    target_dir.mkdir()
    _write_events_jsonl(target_dir / "events.jsonl", [_user("root")])
    assert cli.main(["scan-baseline", str(target_dir), "--baseline", str(tmp_path / "nope")]) == 1
    assert "scan-baseline failed" in capsys.readouterr().err


def test_detect_merges_baseline_findings(tmp_path):
    target_dir = tmp_path / "t"
    target_dir.mkdir()
    _write_events_jsonl(target_dir / "events.jsonl", [_user("root"), _user("evil")])
    base_dir = tmp_path / "b"
    base_dir.mkdir()
    _write_events_jsonl(base_dir / "events.jsonl", [_user("root")])
    out = tmp_path / "detect-out"
    assert cli.main(["detect", str(target_dir), "-o", str(out), "--baseline", str(base_dir)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    drift = [f for f in findings if f["rule"] == "baseline_users"]
    assert len(drift) == 1
    assert "evil" in drift[0]["title"]


def test_run_merges_baseline_findings(tmp_path):
    base_root = make_mini_evidence(
        tmp_path / "base",
        files={"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
    )
    target_root = make_mini_evidence(
        tmp_path / "target",
        files={"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\nevil:x:1001:1001::/tmp:/bin/sh\n"},
    )
    out = tmp_path / "run-out"
    assert cli.main(["run", str(target_root), "-o", str(out), "--baseline", str(base_root)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    drift = [f for f in findings if f["rule"] == "baseline_users"]
    assert len(drift) == 1
    assert "evil" in drift[0]["title"]
    assert drift[0]["refs"][0]["evidence_path"] == "/etc/passwd"


def test_run_without_baseline_unchanged(tmp_path):
    root = make_mini_evidence(
        tmp_path / "mini",
        files={"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
    )
    out = tmp_path / "run-plain"
    assert cli.main(["run", str(root), "-o", str(out)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert all(not f["rule"].startswith("baseline_") for f in findings)
