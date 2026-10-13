import csv
import json
import time
import tracemalloc
from datetime import UTC, datetime, timedelta

import pytest
from conftest import make_mini_evidence

from linuxdfir import cli
from linuxdfir.ingest import Evidence
from linuxdfir.parsers import auth_log
from linuxdfir.schema import Event, Finding, Ref, Severity
from linuxdfir.timeline import Timeline

COLLECTION = datetime(2026, 1, 3, 6, 0, 0, tzinfo=UTC)


def _ev(ts=None, artifact="auth_log", etype="ssh_failed_login", user="root", path="/var/log/auth.log", line=1, msg="m"):
    return Event(
        timestamp_utc=ts,
        host="h",
        user=user,
        source_artifact=artifact,
        event_type=etype,
        message=msg,
        evidence_path=path,
        line_or_offset=line,
        raw="r",
    )


def _build(tmp_path, events, name="timeline.db"):
    return Timeline.build(tmp_path / name, iter(events), collection_time_utc=COLLECTION)


def test_ordering_and_stable_ties(tmp_path):
    jan2 = datetime(2026, 1, 2, 1, 0, tzinfo=UTC)
    jan1 = datetime(2026, 1, 1, 1, 0, tzinfo=UTC)
    events = [
        _ev(jan2, artifact="syslog", path="/var/log/syslog", line=3, msg="c"),
        _ev(jan1, artifact="auth_log", path="/var/log/auth.log", line=9, msg="a"),
        _ev(jan2, artifact="auth_log", path="/var/log/auth.log", line=2, msg="b2"),
        _ev(jan2, artifact="auth_log", path="/var/log/auth.log", line=1, msg="b1"),
    ]
    with _build(tmp_path, events) as timeline:
        ordered = list(timeline.iter_ordered())
    assert [(e.timestamp_utc, e.source_artifact, e.line_or_offset) for e in ordered] == [
        (jan1, "auth_log", 9),
        (jan2, "auth_log", 1),
        (jan2, "auth_log", 2),
        (jan2, "syslog", 3),
    ]


def test_undated_kept_separately(tmp_path):
    events = [_ev(datetime(2026, 1, 2, tzinfo=UTC), line=1), _ev(None, line=2), _ev(None, line=3)]
    with _build(tmp_path, events) as timeline:
        assert [e.line_or_offset for e in timeline.iter_ordered()] == [1]
        assert [e.line_or_offset for e in timeline.iter_undated()] == [2, 3]
        assert timeline.undated_count() == 2
        assert timeline.stats()["undated"] == 2


def test_dec31_jan1_ordering(tmp_path):
    dec = datetime(2025, 12, 31, 21, 58, 44, tzinfo=UTC)
    jan = datetime(2025, 12, 31, 22, 3, 12, tzinfo=UTC)
    with _build(tmp_path, [_ev(jan, line=2), _ev(dec, line=1)]) as timeline:
        assert [e.line_or_offset for e in timeline.iter_ordered()] == [1, 2]


def test_dst_boundary_end_to_end(tmp_path):
    root = make_mini_evidence(
        tmp_path / "mini",
        tz_name="America/New_York",
        tz_offset=-18000,
        files={
            "/var/log/auth.log": (
                b"Mar  8 01:59:00 web01 sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
                b"Mar  8 03:01:00 web01 sshd[2]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
            )
        },
        collection_time_utc="2026-04-01T06:00:00Z",
    )
    with Evidence.open(root) as evidence:
        assert str(evidence.tzinfo.key) == "America/New_York"
        events = list(auth_log.parse_member(evidence, "evidence/var/log/auth.log"))
    assert [e.timestamp_utc for e in events] == [
        datetime(2026, 3, 8, 6, 59, tzinfo=UTC),
        datetime(2026, 3, 8, 7, 1, tzinfo=UTC),
    ]
    with _build(tmp_path, events) as timeline:
        assert [e.line_or_offset for e in timeline.iter_ordered()] == [1, 2]


def test_suspicious_time_flags(tmp_path):
    ancient = datetime(1999, 6, 1, tzinfo=UTC)
    future = COLLECTION + timedelta(days=2)
    edge = COLLECTION + timedelta(days=1)
    events = [_ev(ancient, line=1), _ev(future, line=2), _ev(edge, line=3), _ev(None, line=4)]
    with _build(tmp_path, events) as timeline:
        assert sorted(e.line_or_offset for e in timeline.iter_suspicious()) == [1, 2]
        assert timeline.stats()["suspicious_time"] == 2


def test_dedup_exact_duplicates_only(tmp_path):
    base = _ev(datetime(2026, 1, 2, tzinfo=UTC), line=9, msg="Failed password for root from 1.1.1.1 port 5")
    other_msg = _ev(datetime(2026, 1, 2, tzinfo=UTC), line=9, msg="different")
    other_artifact = _ev(
        datetime(2026, 1, 2, tzinfo=UTC), line=9, msg="Failed password for root from 1.1.1.1 port 5", artifact="syslog"
    )
    timeline = Timeline(tmp_path / "t.db")
    try:
        result = timeline.add_events(iter([base, base, other_msg, other_artifact]), COLLECTION)
        assert result == {"attempted": 4, "stored": 3, "duplicates": 1}
        assert len(timeline) == 3
    finally:
        timeline.close()


def test_query_filters(tmp_path):
    t0 = datetime(2026, 1, 2, 1, 0, tzinfo=UTC)
    events = [
        _ev(t0, user="root", etype="ssh_failed_login", msg="Failed from 10.9.9.9", line=1),
        _ev(t0 + timedelta(minutes=5), user="alice", etype="ssh_accepted_login", line=2),
        _ev(t0 + timedelta(minutes=10), user="root", etype="sudo_command", artifact="sudo", line=3),
    ]
    with _build(tmp_path, events) as timeline:
        assert [e.line_or_offset for e in timeline.query(user="root")] == [1, 3]
        assert [e.line_or_offset for e in timeline.query(event_type="ssh_accepted_login")] == [2]
        assert [e.line_or_offset for e in timeline.query(source_artifact="sudo")] == [3]
        assert [e.line_or_offset for e in timeline.query(ip="10.9.9.9")] == [1]
        assert [e.line_or_offset for e in timeline.query(start=t0 + timedelta(minutes=1))] == [2, 3]
        assert [e.line_or_offset for e in timeline.query(end=t0 + timedelta(minutes=6))] == [1, 2]
        assert [e.line_or_offset for e in timeline.query(user="root", event_type="sudo_command")] == [3]
        assert [e.line_or_offset for e in timeline.query(limit=2)] == [1, 2]
        with pytest.raises(ValueError):
            list(timeline.query(start=datetime(2026, 1, 2, 1, 0)))


def test_around_and_around_finding(tmp_path):
    t0 = datetime(2026, 1, 2, 1, 10, tzinfo=UTC)
    events = [_ev(t0 + timedelta(minutes=m), line=m) for m in (0, 10, 20, 60, 120)]
    with _build(tmp_path, events) as timeline:
        assert [e.line_or_offset for e in timeline.around(t0 + timedelta(minutes=10), minutes=15)] == [0, 10, 20]
        finding = Finding(
            id="x",
            rule="ssh_bruteforce_then_success",
            severity=Severity.CRITICAL,
            title="t",
            description="d",
            first_seen=t0,
            last_seen=t0 + timedelta(minutes=20),
            refs=[Ref("/var/log/auth.log", 1)],
        )
        assert [e.line_or_offset for e in timeline.around_finding(finding, minutes=5)] == [0, 10, 20]
        timeless = Finding(id="y", rule="r", severity=Severity.INFO, title="t", description="d")
        assert list(timeline.around_finding(timeless)) == []


def test_csv_jsonl_roundtrip(tmp_path):
    tricky = _ev(
        datetime(2026, 1, 2, 1, 0, tzinfo=UTC),
        line=1,
        msg="a,b\nc;d",
        user="root",
    )
    tricky.tags = ["ssh", "auth"]
    tricky.mitre_ids = ["T1110"]
    tricky.repeat_count = 5
    events = [tricky, _ev(None, line=2, msg="undated")]
    with _build(tmp_path, events) as timeline:
        assert timeline.write_jsonl(tmp_path / "events.jsonl") == 2
        assert timeline.write_csv(tmp_path / "timeline.csv") == 2
    rows = list(csv.DictReader(open(tmp_path / "timeline.csv", encoding="utf-8")))
    assert rows[0]["message"] == "a,b\nc;d"
    assert rows[0]["tags"] == "ssh;auth" and rows[0]["mitre_ids"] == "T1110"
    assert rows[0]["repeat_count"] == "5" and rows[0]["suspicious_time"] == "0"
    assert rows[1]["timestamp_utc"] == "" and rows[1]["timestamp_quality"] == "none"
    assert len(rows) == 2
    back = [json.loads(line) for line in open(tmp_path / "events.jsonl", encoding="utf-8")]
    assert [row["line_or_offset"] for row in back] == [1, 2]
    assert back[0]["repeat_count"] == 5


def test_row_json_matches_event_json(tmp_path):
    from linuxdfir import timeline as timeline_mod

    tricky = _ev(datetime(2026, 1, 2, 1, 0, tzinfo=UTC), line=7, msg="x")
    tricky.tags = ["a", "b"]
    tricky.mitre_ids = ["T1"]
    events = [tricky, _ev(None, line="rec-3", msg="y"), _ev(datetime(2026, 1, 2, 2, 0, tzinfo=UTC), line=None)]
    timeline = Timeline(tmp_path / "t.db")
    try:
        timeline.add_events(iter(events), COLLECTION)
        rows = list(timeline.conn.execute("SELECT * FROM events ORDER BY id"))
        assert len(rows) == 3
        for row, event in zip(rows, events, strict=True):
            assert json.loads(timeline_mod._row_to_json(row)) == json.loads(event.to_json())
    finally:
        timeline.close()


def test_stats_contents(tmp_path):
    day2 = datetime(2026, 1, 2, 1, 0, tzinfo=UTC)
    events = [
        _ev(day2, artifact="auth_log", line=1),
        _ev(day2, artifact="auth_log", line=2),
        _ev(datetime(2026, 1, 3, 1, 0, tzinfo=UTC), artifact="syslog", line=1),
        _ev(None, artifact="auth_log", line=3),
    ]
    with _build(tmp_path, events) as timeline:
        stats = timeline.stats()
    assert stats["total"] == 4 and stats["dated"] == 3 and stats["undated"] == 1
    assert stats["per_artifact"] == {"auth_log": 3, "syslog": 1}
    assert stats["per_day"] == {"2026-01-02": 2, "2026-01-03": 1}
    assert stats["suspicious_time"] == 0


def _big_stream(total=500000):
    base = datetime(2026, 1, 1, tzinfo=UTC)
    span = 60 * 86400
    for i in range(total):
        if i % 100 == 0:
            stamp = None
        elif i % 50000 == 25001:
            stamp = datetime(1999, 6, 1, tzinfo=UTC)
        else:
            stamp = base + timedelta(seconds=(i * 7919) % span)
        event = _ev(stamp, line=i, msg=f"event {i} from 10.0.0.{i % 250}", user=f"user{i % 50}")
        yield event
        if i % 2000 == 0:
            yield event


def test_large_stream_stays_bounded(tmp_path):
    tracemalloc.start()
    started = time.perf_counter()
    collection = datetime(2026, 3, 3, 6, 0, tzinfo=UTC)
    timeline = Timeline(tmp_path / "big.db")
    try:
        result = timeline.add_events(_big_stream(), collection)
        elapsed = time.perf_counter() - started
        assert result["attempted"] == 500250
        assert result["stored"] == 500000
        assert result["duplicates"] == 250
        assert len(timeline) == 500000
        assert timeline.undated_count() == 5000
        assert timeline.stats()["suspicious_time"] == 10
        first = next(timeline.iter_ordered())
        assert first.timestamp_utc == datetime(1999, 6, 1, tzinfo=UTC)
        assert timeline.write_jsonl(tmp_path / "events.jsonl") == 500000
        assert timeline.write_csv(tmp_path / "timeline.csv") == 500000
        window = list(
            timeline.query(start=datetime(2026, 1, 10, tzinfo=UTC), end=datetime(2026, 1, 11, tzinfo=UTC), limit=5)
        )
        assert len(window) == 5
        _, peak = tracemalloc.get_traced_memory()
    finally:
        timeline.close()
        tracemalloc.stop()
    assert elapsed < 240, f"500k pipeline took {elapsed:.1f}s"
    assert peak < 300 * 1024 * 1024, f"peak traced memory {peak / 1024 / 1024:.1f} MiB"


def test_cli_parse_writes_timeline_outputs(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    out = tmp_path / "parsed"
    assert cli.main(["parse", str(archive), "-o", str(out)]) == 0
    assert (out / "timeline.db").is_file()
    assert (out / "timeline.csv").is_file()
    stats = json.loads((out / "timeline_stats.json").read_text(encoding="utf-8"))
    assert stats["total"] == 65 and stats["undated"] == 0
    assert stats["per_artifact"] == {"auth_log": 65}
    assert stats["parser_error_count"] == 0
    assert stats["suspicious_time"] == 0
