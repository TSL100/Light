"""syslog / kern.log parser: traditional + ISO formats, kernel classification.

Reuses the timeutil year/TZ logic (collection year assumed, roll back when
more than a day past collection). Kernel lines are classified into module
loads, OOM kills, oopses, USB activity and generic kernel messages; CRON
CMD and systemd unit lines get their own event types. ``last message
repeated N times`` lines bump repeat_count on the previous event.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..ingest import Evidence
from ..schema import Event
from ..timeutil import SyslogYearTracker, parse_iso8601, parse_syslog_prefix

PARSER_NAME = "syslog_kern"
CONSUMES = ["syslog", "kern_log"]

ISO_LINE_RE = re.compile(r"^(\S+) (\S+) ([^\[:]+?)(?:\[(\d+)\])?: (.*)$")
REPEAT_RE = re.compile(r"last message repeated (\d+) times?")
KERNEL_TS_RE = re.compile(r"^\[\s*\d+\.\d+\]\s*")
CRON_CMD_RE = re.compile(r"^\(([^)]+)\) CMD \((.*)\)$")
SESSION_USER_RE = re.compile(r"session opened for user (\S+)")
SYSTEMD_UNIT_RE = re.compile(r"\b([A-Za-z0-9_@:-]+\.(?:service|socket|timer|target|mount|slice|scope))\b")
SYSTEMD_ACTION_RE = re.compile(
    r"\b(Starting|Started|Stopping|Stopped|Reloading|Reloaded|Failed|Reached|Mounting|Mounted)\b"
)
MODULE_SIGNAL_RE = re.compile(
    r"out-of-tree|taints kernel|disagrees about version|unsigned|staging|loading .*\.ko", re.IGNORECASE
)
MODULE_NAME_RE = re.compile(r"^(\S+?):\s")
OOM_RE = re.compile(r"Out of memory|oom-killer|Killed process|invoked oom-killer", re.IGNORECASE)
OOPS_RE = re.compile(r"\bOops\b|BUG:|WARNING: CPU|Call Trace|kernel panic", re.IGNORECASE)
USB_RE = re.compile(r"\b[uU][sS][bB]\b|new .*USB device|USB Mass Storage", re.IGNORECASE)
KERNEL_MODULE_MESSAGE_RE = re.compile(r"^kernel module (\S+?): (.*)$")


def parse_kernel_module_message(message: str) -> dict | None:
    """Split a canonical kernel_module message into name/detail."""
    match = KERNEL_MODULE_MESSAGE_RE.match(message)
    if not match:
        return None
    return {"name": match.group(1), "detail": match.group(2)}


def _classify_kernel(proc: str, text: str) -> tuple[str, str | None]:
    detail = KERNEL_TS_RE.sub("", text).strip()
    if proc in ("insmod", "modprobe"):
        name = detail.split()[0].rstrip(":") if detail.split() else "unknown"
        return "kernel_module", f"kernel module {name}: invoked via {proc}: {detail}"
    if MODULE_SIGNAL_RE.search(detail):
        name_match = MODULE_NAME_RE.match(detail)
        name = name_match.group(1) if name_match else "unknown"
        return "kernel_module", f"kernel module {name}: {detail}"
    if OOM_RE.search(detail):
        return "kernel_oom", f"kernel OOM: {detail[:400]}"
    if OOPS_RE.search(detail):
        return "kernel_error", f"kernel error: {detail[:400]}"
    if USB_RE.search(detail):
        return "kernel_usb", f"kernel USB: {detail[:400]}"
    return "kernel_message", f"kernel: {detail[:500]}"


def _classify(proc: str, message: str) -> tuple[str, str | None]:
    text = message.strip()
    if proc == "kernel":
        return _classify_kernel(proc, text)
    cron = CRON_CMD_RE.match(text)
    if cron and proc.upper().startswith("CRON"):
        user, command = cron.groups()
        return "cron_command", f"{user}:{command.strip()}"
    if proc == "systemd" and SYSTEMD_ACTION_RE.search(text):
        return "systemd_unit_action", None
    session = SESSION_USER_RE.search(text)
    if session:
        return "syslog_message", session.group(1)
    return "syslog_message", None


def _build(
    evidence: Evidence,
    member: str,
    lineno: int,
    line: str,
    proc: str,
    pid: int | None,
    message: str,
    timestamp_utc,
    quality: str,
    tz_tag: str | None,
) -> Event:
    event_type, extra = _classify(proc, message)
    if event_type == "cron_command" and extra is not None:
        user, command = extra.split(":", 1)
        text, user = f"cron ({user}): {command}", user
    elif event_type == "kernel_module":
        text, user = extra, None
    else:
        text, user = message.strip()[:500], extra
    confidence = 1.0 if event_type != "syslog_message" else 0.6
    tags = [event_type.split("_")[0], "syslog"]
    if tz_tag:
        tags.append(tz_tag)
    return Event(
        timestamp_utc=timestamp_utc,
        host=evidence.context.hostname,
        user=user,
        source_artifact="syslog",
        event_type=event_type,
        message=text,
        evidence_path=evidence.display_path(member),
        line_or_offset=lineno,
        raw=line,
        tags=tags,
        confidence=confidence,
        parser=PARSER_NAME,
        timestamp_quality=quality,
    )


def _unparsed(evidence: Evidence, member: str, lineno: int, line: str) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=None,
        source_artifact="syslog",
        event_type="unparsed",
        message=line.strip()[:500],
        evidence_path=evidence.display_path(member),
        line_or_offset=lineno,
        raw=line,
        tags=["unparsed"],
        confidence=0.1,
        parser=PARSER_NAME,
    )


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0, "repeated": 0})
    tracker = SyslogYearTracker(evidence.context.collection_time_utc, evidence.tzinfo, evidence.tz_source)
    pending: Event | None = None
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        if not line.strip():
            continue
        repeat = REPEAT_RE.search(line.strip())
        if repeat is not None and pending is not None:
            count = int(repeat.group(1))
            pending.repeat_count += count
            stats["repeated"] += count
            continue
        event: Event | None = None
        if line[:1].isdigit():
            match = ISO_LINE_RE.match(line)
            if match is not None:
                stamp, _host, proc, pid, message = match.groups()
                try:
                    timestamp_utc, quality = parse_iso8601(stamp)
                except ValueError:
                    timestamp_utc, quality = None, "none"
                if timestamp_utc is not None:
                    event = _build(
                        evidence, member, lineno, line, proc, int(pid) if pid else None,
                        message, timestamp_utc, quality, None,
                    )
        else:
            prefix = parse_syslog_prefix(line)
            if prefix is not None:
                try:
                    timestamp_utc, quality, tz_tag = tracker.resolve(
                        prefix["month"], prefix["day"], prefix["hour"],
                        prefix["minute"], prefix["second"],
                    )
                except ValueError:
                    timestamp_utc, quality, tz_tag = None, "none", None
                if timestamp_utc is not None:
                    event = _build(
                        evidence, member, lineno, line, prefix["proc"], prefix["pid"],
                        prefix["message"], timestamp_utc, quality, tz_tag,
                    )
        if event is None:
            event = _unparsed(evidence, member, lineno, line)
            stats["unparsed"] += 1
        stats["events"] += 1
        pending = event
        yield event
