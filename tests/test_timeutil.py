from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from linuxdfir.timeutil import (
    SyslogYearTracker,
    parse_iso8601,
    parse_syslog_prefix,
    resolve_syslog_timestamp,
)

CAIRO = ZoneInfo("Africa/Cairo")
COLLECTION = datetime(2026, 1, 3, 6, 0, 0, tzinfo=UTC)


def test_dec31_rolls_back_to_prior_year():
    stamp, quality, tag = resolve_syslog_timestamp("Dec", 31, 23, 58, 44, COLLECTION, CAIRO, "iana")
    assert stamp == datetime(2025, 12, 31, 21, 58, 44, tzinfo=UTC)
    assert quality == "inferred_year"
    assert tag == "tz_from_manifest"


def test_jan1_keeps_collection_year_and_converts_cairo():
    stamp, quality, tag = resolve_syslog_timestamp("Jan", 1, 0, 3, 12, COLLECTION, CAIRO, "iana")
    assert stamp == datetime(2025, 12, 31, 22, 3, 12, tzinfo=UTC)
    assert stamp.astimezone(CAIRO).year == 2026
    assert quality == "inferred_year"
    assert tag == "tz_from_manifest"


def test_non_iana_source_tags_tz_assumed():
    _, _, tag = resolve_syslog_timestamp("Jan", 2, 3, 10, 7, COLLECTION, CAIRO, "fixed_offset")
    assert tag == "tz_assumed"
    _, _, tag = resolve_syslog_timestamp("Jan", 2, 3, 10, 7, COLLECTION, CAIRO, "utc")
    assert tag == "tz_assumed"


def test_rollback_boundary_one_day_tolerance():
    inside, _, _ = resolve_syslog_timestamp("Jan", 4, 7, 59, 59, COLLECTION, CAIRO, "iana")
    assert inside.year == 2026
    outside, _, _ = resolve_syslog_timestamp("Jan", 4, 8, 0, 1, COLLECTION, CAIRO, "iana")
    assert outside.year == 2025


def test_dst_summer_offset_applies():
    stamp, _, _ = resolve_syslog_timestamp("Jul", 1, 12, 0, 0, datetime(2026, 8, 1, tzinfo=UTC), CAIRO, "iana")
    assert stamp == datetime(2026, 7, 1, 9, 0, 0, tzinfo=UTC)


def test_dst_gap_and_fold_do_not_crash():
    eastern = ZoneInfo("America/New_York")
    collection = datetime(2025, 4, 1, tzinfo=UTC)
    gap, _, _ = resolve_syslog_timestamp("Mar", 9, 2, 30, 0, collection, eastern, "iana")
    assert gap.tzinfo is not None
    fold, _, _ = resolve_syslog_timestamp("Nov", 2, 1, 30, 0, datetime(2025, 12, 1, tzinfo=UTC), eastern, "iana")
    assert fold.tzinfo is not None


def test_invalid_calendar_date_raises():
    with pytest.raises(ValueError):
        resolve_syslog_timestamp("Feb", 30, 0, 0, 0, COLLECTION, CAIRO, "iana")


def test_parse_syslog_prefix_space_padded_day():
    parsed = parse_syslog_prefix(
        "Jan  1 00:03:12 web01 sshd[1910]: pam_unix(sshd:session): session closed for user admin"
    )
    assert parsed is not None
    assert (parsed["month"], parsed["day"]) == (1, 1)
    assert (parsed["host"], parsed["proc"], parsed["pid"]) == ("web01", "sshd", 1910)
    assert parsed["message"].startswith("pam_unix")
    assert parse_syslog_prefix("this is not a log line") is None
    assert parse_syslog_prefix("Foo  1 00:00:00 h p: m") is None


def test_tracker_keeps_years_consistent_across_boundary():
    tracker = SyslogYearTracker(COLLECTION, CAIRO, "iana")
    dec, _, _ = tracker.resolve("Dec", 31, 23, 58, 44)
    jan, _, _ = tracker.resolve("Jan", 1, 0, 3, 12)
    assert dec == datetime(2025, 12, 31, 21, 58, 44, tzinfo=UTC)
    assert jan == datetime(2025, 12, 31, 22, 3, 12, tzinfo=UTC)
    assert jan.astimezone(CAIRO).year == 2026
    assert jan > dec


def test_tracker_never_exceeds_future_bound():
    tracker = SyslogYearTracker(COLLECTION, CAIRO, "iana")
    stamps = [
        tracker.resolve("Jan", 2, 3, 10, 7)[0],
        tracker.resolve("Jan", 3, 5, 0, 0)[0],
        tracker.resolve("Jan", 5, 0, 0, 0)[0],
        tracker.resolve("Dec", 31, 23, 59, 59)[0],
    ]
    assert all(stamp <= COLLECTION + timedelta(days=1) for stamp in stamps)


def test_parse_iso8601_variants():
    stamp, quality = parse_iso8601("2026-01-02T03:12:44+02:00")
    assert (stamp, quality) == (datetime(2026, 1, 2, 1, 12, 44, tzinfo=UTC), "exact")
    stamp, _ = parse_iso8601("2026-01-03T06:00:00.123456+02:00")
    assert stamp == datetime(2026, 1, 3, 4, 0, 0, 123456, tzinfo=UTC)
    stamp, _ = parse_iso8601("2026-01-03T06:00:00Z")
    assert stamp == datetime(2026, 1, 3, 6, 0, 0, tzinfo=UTC)
    stamp, _ = parse_iso8601("2026-01-02T03:12:44+0200")
    assert stamp == datetime(2026, 1, 2, 1, 12, 44, tzinfo=UTC)
    with pytest.raises(ValueError):
        parse_iso8601("2026-01-02T03:12:44")
    with pytest.raises(ValueError):
        parse_iso8601("not a timestamp")
