import json
from datetime import UTC, datetime

import pytest

from linuxdfir.schema import (
    TIMESTAMP_QUALITIES,
    Event,
    Finding,
    Ref,
    Severity,
    artifacts_for_path,
    make_finding_id,
    match_artifact,
    parse_severity,
    severity_rank,
)

UTC = UTC


def test_severity_values_and_rank():
    assert [s.value for s in Severity] == ["info", "low", "medium", "high", "critical"]
    assert severity_rank(Severity.INFO) < severity_rank(Severity.LOW) < severity_rank(Severity.MEDIUM)
    assert severity_rank(Severity.MEDIUM) < severity_rank(Severity.HIGH) < severity_rank(Severity.CRITICAL)
    assert parse_severity("HIGH") is Severity.HIGH
    assert parse_severity("info") is Severity.INFO
    with pytest.raises(ValueError):
        parse_severity("bogus")


def test_event_round_trip():
    event = Event(
        timestamp_utc=datetime(2026, 1, 2, 1, 12, 44, tzinfo=UTC),
        host="web01",
        user="root",
        source_artifact="auth_log",
        event_type="ssh_login_success",
        message="Accepted password for root",
        evidence_path="/var/log/auth.log",
        line_or_offset=55,
        raw="Jan  2 03:12:44 web01 sshd[4150]: Accepted ...",
        tags=["auth", "ssh"],
        mitre_ids=["T1110"],
        confidence=0.9,
        parser="auth_log",
        timestamp_quality="tz_assumed",
    )
    restored = Event.from_dict(json.loads(event.to_json()))
    assert restored == event
    assert restored.timestamp_utc.tzinfo is not None


def test_event_undated_gets_quality_none():
    event = Event(
        timestamp_utc=None,
        host="web01",
        user=None,
        source_artifact="bash_history",
        event_type="suspicious_command",
        message="curl|bash",
        evidence_path="/home/alice/.bash_history",
        line_or_offset=4,
    )
    assert event.timestamp_quality == "none"
    assert Event.from_dict(event.to_dict()).timestamp_utc is None
    assert set(TIMESTAMP_QUALITIES) == {"exact", "inferred_year", "tz_assumed", "none"}


def test_event_validation():
    with pytest.raises(ValueError):
        Event(
            timestamp_utc=datetime(2026, 1, 2, 1, 0, 0),
            host="h",
            user="u",
            source_artifact="a",
            event_type="e",
            message="m",
            evidence_path="/p",
        )
    with pytest.raises(ValueError):
        Event(
            timestamp_utc=None,
            host="h",
            user="u",
            source_artifact="a",
            event_type="e",
            message="m",
            evidence_path="/p",
            timestamp_quality="someday",
        )
    with pytest.raises(ValueError):
        Event(
            timestamp_utc=None,
            host="h",
            user="u",
            source_artifact="a",
            event_type="e",
            message="m",
            evidence_path="/p",
            confidence=1.5,
        )


def test_finding_round_trip():
    finding = Finding(
        id=make_finding_id("ssh_bruteforce", "web01", "203.0.113.9"),
        rule="ssh_bruteforce",
        severity="HIGH",
        title="SSH brute force then success",
        description="48 failures then success",
        mitre_ids=["T1110"],
        first_seen=datetime(2026, 1, 2, 1, 10, tzinfo=UTC),
        last_seen=datetime(2026, 1, 2, 1, 12, tzinfo=UTC),
        count=49,
        refs=[Ref("/var/log/auth.log", 12), Ref("/var/log/auth.log", 60)],
    )
    assert finding.severity is Severity.HIGH
    restored = Finding.from_dict(json.loads(json.dumps(finding.to_dict())))
    assert restored == finding
    assert make_finding_id("r", "a") == make_finding_id("r", "a")
    assert make_finding_id("r", "a") != make_finding_id("r", "b")


def test_registry_matches_expected_paths():
    assert match_artifact("auth_log", original_path="/var/log/auth.log")
    assert match_artifact("auth_log", original_path="/var/log/auth.log.1")
    assert match_artifact("auth_log", original_path="/var/log/auth.log.2.gz")
    assert not match_artifact("auth_log", original_path="/var/log/syslog")
    assert match_artifact("bash_history", original_path="/home/alice/.bash_history")
    assert match_artifact("bash_history", original_path="/root/.bash_history")
    assert match_artifact("cron", original_path="/etc/cron.d/evil")
    assert match_artifact("cron", original_path="/var/spool/cron/crontabs/root")
    assert match_artifact("systemd_unit", original_path="/etc/systemd/system/auditd.service")
    assert match_artifact("sudoers", original_path="/etc/sudoers.d/99-backup")
    assert match_artifact("ssh", original_path="/root/.ssh/authorized_keys")
    assert match_artifact("recent_files", archive_path="triage/recent_files.txt")
    assert match_artifact("live_ps", archive_path="live/ps_auxf.txt")
    assert match_artifact("live_crontab", archive_path="live/crontab_root.txt")
    assert "cron" in artifacts_for_path(original_path="/etc/cron.d/evil")
    assert "systemd_unit" in artifacts_for_path(original_path="/etc/systemd/system/auditd.service")
    assert "live_ps" in artifacts_for_path(archive_path="live/ps_auxf.txt")
    assert artifacts_for_path(original_path="/nope/nothing") == []
