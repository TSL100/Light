import gzip
import inspect
import itertools
import json
from datetime import UTC, datetime
from pathlib import Path

from conftest import FIXTURES_DIR, make_mini_evidence

from linuxdfir import cli
from linuxdfir.detectors import ssh_bruteforce
from linuxdfir.ingest import Evidence
from linuxdfir.parsers import auth_log, iter_members
from linuxdfir.schema import Event, Severity


def parse_fixture_events(tmp_path):
    data = (FIXTURES_DIR / "auth_sample.log").read_bytes()
    root = make_mini_evidence(tmp_path / "mini", files={"/var/log/auth.log": data})
    with Evidence.open(root) as evidence:
        return list(auth_log.parse_member(evidence, "evidence/var/log/auth.log"))


def test_fixture_event_types_and_fields(tmp_path):
    events = parse_fixture_events(tmp_path)
    assert len(events) == 29
    by_line = {event.line_or_offset: event for event in events}
    assert by_line[1].event_type == "ssh_accepted_login"
    assert by_line[1].user == "admin"
    assert by_line[1].timestamp_utc == datetime(2025, 12, 31, 21, 58, 44, tzinfo=UTC)
    assert by_line[1].timestamp_quality == "inferred_year"
    assert "tz_from_manifest" in by_line[1].tags
    assert by_line[2].event_type == "session_closed"
    assert by_line[3].event_type == "ssh_failed_login"
    assert "invalid user admin" in by_line[3].message
    assert by_line[4].user == "root"
    assert by_line[5].user == "test"
    assert by_line[5].message.endswith("from 2001:db8::1 port 443")
    assert by_line[6].user == "foo bar"
    assert by_line[7].user == "admin<script>alert(1)</script>"
    assert "<script>" in by_line[7].raw
    assert by_line[8].event_type == "ssh_invalid_user"
    assert by_line[8].user == "foo bar"
    assert by_line[9].event_type == "ssh_accepted_login"
    assert by_line[10].event_type == "session_opened"
    assert by_line[11].event_type == "su_session"
    assert "session_opened" in by_line[11].tags
    assert by_line[12].event_type == "su_session"
    assert by_line[13].event_type == "sudo_command"
    assert by_line[13].user == "alice"
    assert "/bin/bash" in by_line[13].message
    assert by_line[14].event_type == "sudo_auth_failure"
    assert by_line[14].user == "bob"
    assert by_line[15].event_type == "ssh_disconnect"
    assert by_line[15].user == "admin"
    assert by_line[16].event_type == "ssh_disconnect"
    assert by_line[16].user is None
    assert by_line[17].event_type == "ssh_disconnect"
    assert by_line[18].event_type == "session_opened"
    assert by_line[19].event_type == "cron_command"
    assert by_line[19].user == "root"
    assert "/tmp/.x/run.sh" in by_line[19].message
    assert by_line[20].event_type == "useradd" and by_line[20].user == "evil"
    assert by_line[21].event_type == "groupadd"
    assert by_line[22].event_type == "passwd" and by_line[22].user == "evil"
    assert by_line[23].event_type == "usermod" and by_line[23].user == "evil"
    iso = by_line[24]
    assert iso.event_type == "ssh_accepted_login"
    assert iso.timestamp_utc == datetime(2026, 1, 2, 1, 16, 0, tzinfo=UTC)
    assert iso.timestamp_quality == "exact"
    assert "tz_from_manifest" not in iso.tags and "tz_assumed" not in iso.tags
    assert by_line[25].event_type == "ssh_failed_login"
    assert by_line[25].repeat_count == 5
    assert by_line[29].event_type == "ssh_failed_login"
    assert by_line[29].user == "root"
    for lineno in (27, 28, 30):
        assert by_line[lineno].event_type == "unparsed"
        assert by_line[lineno].timestamp_utc is None
    for event in events:
        assert event.evidence_path == "/var/log/auth.log"
        assert event.host == "mini"
        assert event.parser == "auth_log"
        assert event.source_artifact == "auth_log"


def test_repeat_without_previous_event_is_orphan_unparsed(tmp_path):
    root = make_mini_evidence(
        tmp_path / "mini",
        files={"/var/log/auth.log": b"Jan  2 03:17:01 web01 rsyslogd: last message repeated 4 times\n"},
    )
    with Evidence.open(root) as evidence:
        events = list(auth_log.parse_member(evidence, "evidence/var/log/auth.log"))
    assert len(events) == 1 and events[0].event_type == "unparsed"


def test_rotation_order_oldest_first(tmp_path):
    root = make_mini_evidence(
        tmp_path / "mini",
        files={
            "/var/log/auth.log": b"Jan  2 03:10:07 web01 sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n",
            "/var/log/auth.log.1": (
                b"Dec 31 23:58:44 web01 sshd[2]: Accepted publickey for admin from 10.0.0.7 port 2 ssh2\n"
            ),
            "/var/log/auth.log.2.gz": gzip.compress(
                b"Dec 30 06:25:01 web01 CRON[3]: pam_unix(cron:session): session opened for user root by (uid=0)\n"
            ),
        },
    )
    with Evidence.open(root) as evidence:
        members = list(iter_members(evidence, auth_log.CONSUMES))
        assert [Path(m).name for m in members] == ["auth.log.2.gz", "auth.log.1", "auth.log"]
        stamps = []
        for member in members:
            stamps.extend(event.timestamp_utc for event in auth_log.parse_member(evidence, member))
    assert stamps == sorted(stamps)
    assert stamps[0].year == 2025 and stamps[-1].year == 2026


def test_parser_is_streaming(tmp_path):
    assert inspect.isgeneratorfunction(auth_log.parse_member)
    lines = b"Jan  2 03:10:07 web01 sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n" * 100000
    root = make_mini_evidence(tmp_path / "mini", files={"/var/log/auth.log": lines})
    with Evidence.open(root) as evidence:
        head = list(itertools.islice(auth_log.parse_member(evidence, "evidence/var/log/auth.log"), 5))
        assert len(head) == 5 and all(e.line_or_offset <= 5 for e in head)
        stats: dict = {}
        count = sum(1 for _ in auth_log.parse_member(evidence, "evidence/var/log/auth.log", stats=stats))
    assert count == 100000
    assert stats["lines"] == 100000 and stats["unparsed"] == 0


_seq = 0


def _failed(ip, user, minute, method="password", repeat=1, day=2, hour=1):
    global _seq
    _seq += 1
    return Event(
        timestamp_utc=datetime(2026, 1, day, hour, minute, tzinfo=UTC),
        host="h",
        user=user,
        source_artifact="auth_log",
        event_type="ssh_failed_login",
        message=f"Failed {method} for {user} from {ip} port 50000",
        evidence_path="/var/log/auth.log",
        line_or_offset=_seq,
        raw="raw",
        repeat_count=repeat,
    )


def _accepted(ip, user, minute, hour=1):
    global _seq
    _seq += 1
    return Event(
        timestamp_utc=datetime(2026, 1, 2, hour, minute, tzinfo=UTC),
        host="h",
        user=user,
        source_artifact="auth_log",
        event_type="ssh_accepted_login",
        message=f"Accepted password for {user} from {ip} port 22",
        evidence_path="/var/log/auth.log",
        line_or_offset=_seq,
        raw="raw",
    )


def test_bruteforce_without_success_is_medium():
    events = [_failed("10.1.1.1", "root", minute) for minute in range(11)]
    findings = ssh_bruteforce.detect(events)
    assert [f.rule for f in findings] == ["ssh_bruteforce"]
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].count == 11
    assert findings[0].mitre_ids == ["T1110.001"]


def test_success_for_plain_user_is_high():
    events = [_failed("10.1.1.2", "alice", minute) for minute in range(10)]
    events.append(_accepted("10.1.1.2", "alice", 11))
    findings = ssh_bruteforce.detect(events)
    assert [f.rule for f in findings] == ["ssh_bruteforce_then_success"]
    assert findings[0].severity is Severity.HIGH
    assert findings[0].mitre_ids == ["T1110.001", "T1078"]


def test_success_for_root_or_sudo_user_is_critical():
    events = [_failed("10.1.1.3", "root", minute) for minute in range(10)]
    events.append(_accepted("10.1.1.3", "root", 11))
    assert ssh_bruteforce.detect(events)[0].severity is Severity.CRITICAL
    events = [_failed("10.1.1.4", "alice", minute) for minute in range(10)]
    events.append(_accepted("10.1.1.4", "alice", 11))
    assert ssh_bruteforce.detect(events, sudo_users={"alice"})[0].severity is Severity.CRITICAL


def test_repeat_counts_weight_thresholds():
    events = [_failed("10.1.1.5", "root", minute, repeat=4) for minute in range(3)]
    findings = ssh_bruteforce.detect(events)
    assert len(findings) == 1 and findings[0].count == 12


def test_spraying_thresholds_and_undated_skipped():
    users = [f"user{i}" for i in range(5)]
    events = [_failed("10.1.1.6", user, minute) for minute, user in zip([0, 15, 30, 45, 50], users, strict=True)]
    events.append(_failed("10.1.1.6", "ghost", 55))
    events[-1].timestamp_utc = None
    events[-1].timestamp_quality = "none"
    findings = ssh_bruteforce.detect(events)
    assert [f.rule for f in findings] == ["ssh_password_spraying"]
    assert findings[0].severity is Severity.MEDIUM
    events = [_failed("10.1.1.7", f"user{i}", i * 5) for i in range(10)]
    assert ssh_bruteforce.detect(events)[0].severity is Severity.HIGH


def test_loopback_source_reported():
    events = [_failed("127.0.0.1", "root", minute) for minute in range(10)]
    findings = ssh_bruteforce.detect(events)
    assert "loopback" in findings[0].description


def test_success_outside_window_is_not_linked():
    events = [_failed("10.1.1.8", "root", minute) for minute in range(10)]
    events.append(_accepted("10.1.1.8", "root", 0, hour=2))
    findings = ssh_bruteforce.detect(events)
    assert [f.rule for f in findings] == ["ssh_bruteforce"]


def test_below_threshold_and_custom_threshold():
    assert ssh_bruteforce.detect([_failed("10.1.1.9", "root", m) for m in range(9)]) == []
    findings = ssh_bruteforce.detect([_failed("10.1.1.9", "root", m) for m in range(3)], fail_threshold=3)
    assert [f.rule for f in findings] == ["ssh_bruteforce"]


def test_infected_host_end_to_end(generated):
    archive = generated["results"]["infected"]["archive"]
    with Evidence.open(archive) as evidence:
        members = list(iter_members(evidence, auth_log.CONSUMES))
        assert [Path(m).name for m in members] == ["auth.log.1", "auth.log"]
        events = [event for member in members for event in auth_log.parse_member(evidence, member)]
    assert all(
        e.timestamp_quality == "inferred_year" and "tz_from_manifest" in e.tags
        for e in events
        if e.timestamp_utc
    )
    findings = ssh_bruteforce.detect(events)
    assert sorted(f.rule for f in findings) == ["ssh_bruteforce_then_success", "ssh_password_spraying"]
    success = next(f for f in findings if f.rule == "ssh_bruteforce_then_success")
    assert success.severity is Severity.CRITICAL
    assert success.count == 48
    assert success.mitre_ids == ["T1110.001", "T1078"]
    assert "203.0.113.9" in success.title
    assert success.first_seen == datetime(2026, 1, 2, 1, 10, 7, tzinfo=UTC)
    assert success.last_seen == datetime(2026, 1, 2, 1, 12, 44, tzinfo=UTC)
    assert [ref.line_or_offset for ref in success.refs] == [9, 21, 33, 44, 56, 57]
    assert {ref.evidence_path for ref in success.refs} == {"/var/log/auth.log"}
    spray = next(f for f in findings if f.rule == "ssh_password_spraying")
    assert spray.severity is Severity.MEDIUM
    assert spray.count == 48
    assert "6 distinct users" in spray.description


def test_clean_host_has_no_findings(generated):
    archive = generated["results"]["clean"]["archive"]
    with Evidence.open(archive) as evidence:
        members = list(iter_members(evidence, auth_log.CONSUMES))
        events = [event for member in members for event in auth_log.parse_member(evidence, member)]
    assert any(e.event_type == "ssh_failed_login" for e in events)
    assert ssh_bruteforce.detect(events) == []


def test_cli_parse_and_detect(generated, tmp_path, capsys):
    archive = generated["results"]["infected"]["archive"]
    out = tmp_path / "parsed"
    assert cli.main(["parse", str(archive), "-o", str(out), "--parsers", "auth_log"]) == 0
    lines = (out / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 65
    assert all(json.loads(line)["parser"] == "auth_log" for line in lines)
    assert (out / "parse_stats.json").is_file()
    assert cli.main(["detect", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "ssh_bruteforce_then_success" in printed
    findings_out = tmp_path / "findings"
    assert cli.main(["detect", str(out), "-o", str(findings_out)]) == 0
    findings = json.loads((findings_out / "findings.json").read_text(encoding="utf-8"))
    assert sorted(f["rule"] for f in findings) == ["ssh_bruteforce_then_success", "ssh_password_spraying"]


def test_cli_detect_clean_is_empty(generated, tmp_path):
    archive = generated["results"]["clean"]["archive"]
    out = tmp_path / "parsed"
    assert cli.main(["parse", str(archive), "-o", str(out), "--parsers", "auth_log"]) == 0
    findings_out = tmp_path / "findings"
    assert cli.main(["detect", str(out), "-o", str(findings_out)]) == 0
    findings = json.loads((findings_out / "findings.json").read_text(encoding="utf-8"))
    assert [f for f in findings if f["severity"] in ("HIGH", "CRITICAL")] == []


def test_realworld_formats(tmp_path):
    data = (FIXTURES_DIR / "auth_realworld.log").read_bytes()
    root = make_mini_evidence(tmp_path / "mini", files={"/var/log/auth.log": data})
    with Evidence.open(root) as evidence:
        events = list(auth_log.parse_member(evidence, "evidence/var/log/auth.log"))
    assert len(events) == 5
    by_line = {event.line_or_offset: event for event in events}
    pam_error = by_line[1]
    assert pam_error.event_type == "pam_error"
    assert pam_error.user is None
    assert "dlopen(pam_lastlog.so)" in pam_error.message
    assert pam_error.timestamp_utc == datetime(2026, 10, 13, 15, 18, 27, 706603, tzinfo=UTC)
    assert pam_error.timestamp_quality == "exact"
    opened = by_line[2]
    assert opened.event_type == "session_opened"
    assert opened.user == "root"
    sudo = by_line[3]
    assert sudo.event_type == "sudo_command"
    assert sudo.user == "root"
    assert sudo.message.endswith("/usr/bin/apt install python")
    shutdown = by_line[4]
    assert shutdown.event_type == "system_shutdown"
    assert shutdown.user is None
    assert shutdown.timestamp_utc == datetime(2026, 9, 7, 6, 57, 9, 302778, tzinfo=UTC)
    auth_fail = by_line[5]
    assert auth_fail.event_type == "sudo_auth_failure"
    assert auth_fail.user == "tsl"
    assert auth_fail.timestamp_utc == datetime(2026, 9, 9, 20, 23, 1, 15191, tzinfo=UTC)
    for event in events:
        assert event.evidence_path == "/var/log/auth.log"
        assert event.host == "mini"


def test_reboot_and_halt_variants(tmp_path):
    lines = (
        b"Jan  2 04:00:00 web01 systemd-logind[217]: The system is going down for reboot NOW!\n"
        b"Jan  2 05:00:00 web01 shutdown[300]: shutting down for system halt\n"
    )
    root = make_mini_evidence(tmp_path / "mini", files={"/var/log/auth.log": lines})
    with Evidence.open(root) as evidence:
        events = list(auth_log.parse_member(evidence, "evidence/var/log/auth.log"))
    assert [event.event_type for event in events] == ["system_reboot", "system_shutdown"]
    assert all(event.user is None for event in events)
