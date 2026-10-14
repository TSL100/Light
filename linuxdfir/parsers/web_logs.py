"""Web server logs: nginx/apache access (combined/common) plus error logs.

Access entries become web_request events with the percent-decoded URI in
the message (the raw line is preserved verbatim for evidence). Error
lines become web_error events. Timestamps carry offsets (exact) for
access logs; error-log timestamps are host-local (tz_assumed).
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterator
from datetime import UTC, datetime

from ..ingest import Evidence
from ..schema import Event

PARSER_NAME = "web_logs"
CONSUMES = ["web_logs"]

ACCESS_RE = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] "([A-Z]+) (\S+)(?: \S+)?" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?'
)
NGINX_ERROR_RE = re.compile(
    r"^(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2}) \[(\w+)\] (\d+)#(\d+): (?:\*(\d+) )?(.*)$"
)
NGINX_CLIENT_RE = re.compile(r"client:\s*(\S+?)[,\s]*$")
APACHE_ERROR_RE = re.compile(
    r"^\[(\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] "
    r"\[([^\]]+)\](?: \[pid \d+[^\]]*\])?(?: \[client ([^\]]+)\])? (.*)$"
)
WEB_MESSAGE_RE = re.compile(r"^web (\S+) (.+) -> (\d{3}) from (\S+?)(?: (.*))?$")
UA_RE = re.compile(r'ua="(.*)"$')


def parse_web_message(message: str) -> dict | None:
    """Split a canonical web_request message into its fields."""
    match = WEB_MESSAGE_RE.match(message)
    if not match:
        return None
    method, uri, status, ip, tail = match.groups()
    user_match = re.search(r"user=(\S+)", tail)
    ua_match = UA_RE.search(tail.strip())
    return {
        "method": method,
        "uri": uri,
        "status": int(status),
        "ip": ip,
        "user": user_match.group(1) if user_match else None,
        "ua": ua_match.group(1) if ua_match else "",
    }


def _decode_uri(uri: str) -> str:
    try:
        return urllib.parse.unquote(uri)
    except (ValueError, UnicodeDecodeError):
        return uri


def _unparsed(evidence: Evidence, member: str, lineno: int, line: str) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=None,
        source_artifact="web",
        event_type="unparsed",
        message=line.strip()[:500],
        evidence_path=evidence.display_path(member),
        line_or_offset=lineno,
        raw=line,
        tags=["unparsed"],
        confidence=0.1,
        parser=PARSER_NAME,
    )


def _access_event(evidence, member, display, lineno, line, match) -> Event | None:
    ip, user, stamp, method, uri, status, size, _referer, ua = match.groups()
    try:
        timestamp = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    except ValueError:
        return None
    decoded = _decode_uri(uri)
    message = f"web {method} {decoded} -> {status} from {ip}"
    if user and user != "-":
        message += f" user={user}"
    message += f' ua="{ua or ""}"'
    return Event(
        timestamp_utc=timestamp,
        host=evidence.context.hostname,
        user=user if user and user != "-" else None,
        source_artifact="web",
        event_type="web_request",
        message=message,
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["web", "http"],
        confidence=1.0,
        parser=PARSER_NAME,
        timestamp_quality="exact",
    )


def _error_event(evidence, member, display, lineno, line, timestamp, level, detail, client) -> Event:
    message = f"web error [{level}] {detail.strip()[:300]}"
    if client:
        message += f" client={client}"
    return Event(
        timestamp_utc=timestamp,
        host=evidence.context.hostname,
        user=None,
        source_artifact="web",
        event_type="web_error",
        message=message,
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["web", "error"],
        confidence=1.0,
        parser=PARSER_NAME,
        timestamp_quality="tz_assumed",
    )


def _naive_local(evidence, year, month, day, hour, minute, second):
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=evidence.tzinfo).astimezone(UTC)
    except (ValueError, OverflowError, OSError):
        return None


def _parse_error_line(evidence, member, display, lineno, line, stats) -> Event | None:
    text = line.strip()
    nginx = NGINX_ERROR_RE.match(text)
    if nginx is not None:
        year, mon, day, hour, minute, sec, level, _pid, _tid, _conn, detail = nginx.groups()
        timestamp = _naive_local(evidence, int(year), int(mon), int(day), int(hour), int(minute), int(sec))
        if timestamp is None:
            return None
        client_match = NGINX_CLIENT_RE.search(detail)
        client = client_match.group(1) if client_match else None
        if client_match:
            detail = detail[: client_match.start()].rstrip(", ").strip()
        return _error_event(evidence, member, display, lineno, line, timestamp, level, detail, client)
    apache = APACHE_ERROR_RE.match(text)
    if apache is not None:
        stamp, level, client, detail = apache.groups()
        stamp = re.sub(r"\.\d+", "", stamp)
        try:
            naive = datetime.strptime(stamp, "%a %b %d %H:%M:%S %Y")
        except ValueError:
            return None
        timestamp = _naive_local(evidence, naive.year, naive.month, naive.day, naive.hour, naive.minute, naive.second)
        if timestamp is None:
            return None
        return _error_event(evidence, member, display, lineno, line, timestamp, level.split(":")[0], detail, client)
    return None


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    lowered = display.lower()
    force_error = "error" in lowered and "access" not in lowered
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        if not line.strip():
            continue
        event: Event | None = None
        if not force_error:
            match = ACCESS_RE.match(line.strip())
            if match is not None:
                event = _access_event(evidence, member, display, lineno, line, match)
        if event is None and (force_error or "access" not in lowered):
            event = _parse_error_line(evidence, member, display, lineno, line, stats)
        if event is None:
            event = _unparsed(evidence, member, lineno, line)
            stats["unparsed"] += 1
        stats["events"] += 1
        yield event
