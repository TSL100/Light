"""Shared timestamp helpers for parsers and the timeline.

Year-less syslog timestamps are resolved against the manifest collection
time (never the current clock): the collection year is assumed, and the
result rolls back one full year when it lands more than one day after
collection. Host-local times are converted to UTC with zoneinfo so DST
transitions are handled instead of crashing.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

SYSLOG_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

SYSLOG_PREFIX_RE = re.compile(
    r"^(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([^\[:]+?)(?:\[(\d+)\])?: (.*)$"
)

ROLLBACK_TOLERANCE = timedelta(days=1)


def parse_syslog_prefix(line: str) -> dict | None:
    """Split a traditional syslog line into its prefix fields.

    Returns month/day/time/host/proc/pid/message, or None when the line has
    no syslog prefix. Tolerates space-padded days (``Jan  1``).
    """
    match = SYSLOG_PREFIX_RE.match(line)
    if not match:
        return None
    month, day, hour, minute, second, host, proc, pid, message = match.groups()
    if month not in SYSLOG_MONTHS:
        return None
    return {
        "month": SYSLOG_MONTHS[month],
        "day": int(day),
        "hour": int(hour),
        "minute": int(minute),
        "second": int(second),
        "host": host,
        "proc": proc,
        "pid": int(pid) if pid is not None else None,
        "message": message,
    }


def _tz_tag(tz_source: str) -> str:
    return "tz_from_manifest" if tz_source == "iana" else "tz_assumed"


def resolve_syslog_timestamp(
    month: int | str,
    day: int,
    hour: int,
    minute: int,
    second: int,
    collection_time_utc: datetime,
    tz,
    tz_source: str = "iana",
) -> tuple[datetime, str, str]:
    """Resolve a year-less syslog timestamp to UTC.

    Returns (timestamp_utc, timestamp_quality, tz_tag). The collection year
    is assumed first; when that instant falls more than one day after the
    collection time the year rolls back by one. Raises ValueError for
    impossible calendar dates such as Feb 30.
    """
    if isinstance(month, str):
        month = SYSLOG_MONTHS[month]
    year = collection_time_utc.year
    candidate = datetime(year, month, day, hour, minute, second, tzinfo=tz).astimezone(UTC)
    if candidate > collection_time_utc + ROLLBACK_TOLERANCE:
        candidate = datetime(year - 1, month, day, hour, minute, second, tzinfo=tz).astimezone(UTC)
    return candidate, "inferred_year", _tz_tag(tz_source)


def parse_iso8601(value: str) -> tuple[datetime, str]:
    """Parse an ISO 8601 timestamp with offset into UTC. Raises ValueError."""
    text = value.strip()
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError(f"ISO timestamp has no offset: {value!r}")
    return parsed.astimezone(UTC), "exact"


class SyslogYearTracker:
    """Resolve a sequence of year-less timestamps, oldest log first.

    Per-line inference already handles the Dec/Jan boundary, but a line
    dated far into the future (clock skew, wrong zone) would otherwise roll
    back a whole year behind the lines already seen. The tracker prefers
    continuity: when the independent result would step backwards, it tries
    the same wall time one year forward, keeping it only if it stays within
    one day after collection. The future bound is therefore never violated.
    """

    def __init__(self, collection_time_utc: datetime, tz, tz_source: str = "iana"):
        self.collection_time_utc = collection_time_utc
        self.tz = tz
        self.tz_source = tz_source
        self.last: datetime | None = None

    def resolve(
        self, month: int | str, day: int, hour: int, minute: int, second: int = 0
    ) -> tuple[datetime, str, str]:
        candidate, quality, tag = resolve_syslog_timestamp(
            month, day, hour, minute, second, self.collection_time_utc, self.tz, self.tz_source
        )
        if self.last is not None and candidate < self.last:
            try:
                forward = candidate.replace(year=candidate.year + 1)
            except ValueError:
                forward = candidate + timedelta(days=365)
            if forward <= self.collection_time_utc + ROLLBACK_TOLERANCE:
                candidate = forward
        if self.last is None or candidate > self.last:
            self.last = candidate
        return candidate, quality, tag
