"""Binary login records: wtmp/btmp (utmp 384-byte records) and lastlog.

Pure stdlib struct parsing from bytes: 384-byte little-endian utmp
records, lastlog tables in 64-bit (296-byte) or 32-bit (292-byte) layout
detected by file size. Truncated tails and corrupt records are counted
in stats and skipped, never fatal. Timestamps are epoch seconds (exact).
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterator
from datetime import UTC, datetime

from ..ingest import Evidence
from ..schema import Event

PARSER_NAME = "wtmp_btmp_lastlog"
CONSUMES = ["wtmp", "btmp", "lastlog"]

UTMP_FMT = "<h2xi32s4s32s256shhqqq4i8x"
UTMP_SIZE = struct.calcsize(UTMP_FMT)
assert UTMP_SIZE == 384
LASTLOG_FMT_64 = "<q32s256s"
LASTLOG_SIZE_64 = struct.calcsize(LASTLOG_FMT_64)
assert LASTLOG_SIZE_64 == 296
LASTLOG_FMT_32 = "<l32s256s"
LASTLOG_SIZE_32 = struct.calcsize(LASTLOG_FMT_32)
assert LASTLOG_SIZE_32 == 292

UT_RUN_LVL = 1
UT_BOOT_TIME = 2
UT_NEW_TIME = 3
UT_OLD_TIME = 4
UT_INIT_PROCESS = 5
UT_LOGIN_PROCESS = 6
UT_USER_PROCESS = 7
UT_DEAD_PROCESS = 8
UT_ACCOUNTING = 9

def parse_login_message(message: str) -> dict | None:
    """Split a canonical login message into kind/user-or-uid/ip/tty/hour."""
    match = re.match(r"^(login|failed login|last login) (\S+) from (\S+) on (\S+) at (\S+)$", message)
    if not match:
        return None
    kind, who, ip, tty, stamp = match.groups()
    hour_match = re.search(r"T(\d{2}):", stamp)
    result: dict = {"kind": kind, "ip": ip, "tty": tty, "hour": int(hour_match.group(1)) if hour_match else None}
    if kind == "last login":
        uid_match = re.match(r"uid=(\d+)", who)
        result["uid"] = int(uid_match.group(1)) if uid_match else None
        result["user"] = None
    else:
        result["user"] = who
        result["uid"] = None
    return result


def _clean(value: bytes) -> str:
    return value.split(b"\x00")[0].decode("utf-8", errors="replace")


def _sane_ts(value: int, evidence: Evidence) -> bool:
    earliest = int(datetime(2000, 1, 1, tzinfo=UTC).timestamp())
    latest = int(evidence.context.collection_time_utc.timestamp()) + 86400
    return earliest <= value <= latest


def _local_iso(epoch: int, evidence: Evidence) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).astimezone(evidence.tzinfo).isoformat()


def _login_event(evidence, display, kind, event_type, who, host, line_name, epoch, tags) -> Event:
    if kind == "lastlog":
        message = f"last login {who} from {host} on {line_name} at {_local_iso(epoch, evidence)}"
        user = None
    elif event_type == "btmp_failure":
        message = f"failed login {who} from {host} on {line_name} at {_local_iso(epoch, evidence)}"
        user = who
    else:
        message = f"login {who} from {host} on {line_name} at {_local_iso(epoch, evidence)}"
        user = who
    return Event(
        timestamp_utc=datetime.fromtimestamp(epoch, tz=UTC),
        host=evidence.context.hostname,
        user=user,
        source_artifact=kind,
        event_type=event_type,
        message=message,
        evidence_path=display,
        line_or_offset=None,
        raw="",
        tags=tags,
        confidence=1.0,
        parser=PARSER_NAME,
        timestamp_quality="exact",
    )


def _parse_utmp(evidence, member, display, data: bytes, kind: str, stats) -> Iterator[Event]:
    offset = 0
    size = len(data)
    while offset < size:
        chunk = data[offset : offset + UTMP_SIZE]
        if len(chunk) < UTMP_SIZE:
            stats["corrupt"] += 1
            break
        offset += UTMP_SIZE
        stats["lines"] += 1
        try:
            fields = struct.unpack(UTMP_FMT, chunk)
        except struct.error:
            stats["corrupt"] += 1
            continue
        ut_type, _pid, line_b, _id, user_b, host_b, _t1, _t2, _session, tv_sec, _tv_usec = fields[:11]
        if not _sane_ts(tv_sec, evidence):
            stats["corrupt"] += 1
            continue
        user, host, line_name = _clean(user_b), _clean(host_b), _clean(line_b)
        if kind == "btmp":
            stats["events"] += 1
            yield _login_event(evidence, display, kind, "btmp_failure", user or "UNKNOWN", host or "?",
                               line_name or "?", tv_sec, ["auth", "failure"])
        elif ut_type == UT_USER_PROCESS:
            stats["events"] += 1
            yield _login_event(evidence, display, kind, "wtmp_login", user or "UNKNOWN", host or "?",
                               line_name or "?", tv_sec, ["auth", "login"])
        elif ut_type == UT_DEAD_PROCESS:
            stats["events"] += 1
            yield _login_event(evidence, display, kind, "wtmp_logout", user or "UNKNOWN", host or "?",
                               line_name or "?", tv_sec, ["auth", "logout"])
        elif ut_type == UT_BOOT_TIME:
            stats["events"] += 1
            yield _login_event(evidence, display, kind, "wtmp_boot", "reboot", host or "~",
                               line_name or "~", tv_sec, ["auth", "boot"])
        elif ut_type == UT_RUN_LVL:
            continue
        else:
            stats["events"] += 1
            yield _login_event(evidence, display, kind, "wtmp_record", user or "UNKNOWN", host or "?",
                               line_name or "?", tv_sec, ["auth"])


def _parse_lastlog(evidence, member, display, data: bytes, stats) -> Iterator[Event]:
    size = len(data)
    if size == 0:
        return
    if size % LASTLOG_SIZE_64 == 0:
        fmt, rec_size = LASTLOG_FMT_64, LASTLOG_SIZE_64
    elif size % LASTLOG_SIZE_32 == 0:
        fmt, rec_size = LASTLOG_FMT_32, LASTLOG_SIZE_32
    else:
        fmt, rec_size = LASTLOG_FMT_64, LASTLOG_SIZE_64
    offset = 0
    uid = 0
    while offset < size:
        chunk = data[offset : offset + rec_size]
        if len(chunk) < rec_size:
            stats["corrupt"] += 1
            break
        offset += rec_size
        current_uid = uid
        uid += 1
        stats["lines"] += 1
        try:
            epoch, line_b, host_b = struct.unpack(fmt, chunk)
        except struct.error:
            stats["corrupt"] += 1
            continue
        if epoch == 0:
            continue
        if not _sane_ts(epoch, evidence):
            stats["corrupt"] += 1
            continue
        stats["events"] += 1
        yield _login_event(evidence, display, "lastlog", "lastlog_entry", f"uid={current_uid}",
                           _clean(host_b) or "?", _clean(line_b) or "?", epoch, ["auth", "login"])


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0, "corrupt": 0})
    display = evidence.display_path(member)
    try:
        data = evidence.read_bytes(member)
    except Exception:
        stats["corrupt"] += 1
        return
    lowered = display.lower()
    if "lastlog" in lowered:
        yield from _parse_lastlog(evidence, member, display, data, stats)
    elif "btmp" in lowered:
        yield from _parse_utmp(evidence, member, display, data, "btmp", stats)
    else:
        yield from _parse_utmp(evidence, member, display, data, "wtmp", stats)
