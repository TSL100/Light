"""Package manager logs: dpkg.log, apt history.log, yum/dnf logs.

Emits package_install / package_remove / package_update events with the
package name and version. dpkg and apt timestamps are host-local without
an offset, so they resolve against the manifest timezone (tz_assumed);
yum timestamps are year-less and use the syslog year logic.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import PurePosixPath

from ..ingest import Evidence
from ..schema import Event
from ..timeutil import SyslogYearTracker, parse_iso8601

PARSER_NAME = "package_logs"
CONSUMES = ["package_logs"]

DPKG_LINE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) (\S+) (\S+)(?: (.*))?$")
DPKG_INSTALL = {"install", "upgrade"}
DPKG_REMOVE = {"remove", "purge"}
APT_START_RE = re.compile(r"^Start-Date:\s*(\d{4}-\d{2}-\d{2})\s+(\d{2}):(\d{2}):(\d{2})")
APT_CMD_RE = re.compile(r"^Commandline:\s*(.*)$")
APT_PKG_RE = re.compile(r"^(\S+?):\s*(.*)$")
APT_ENTRY_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9+._~:-]*?)(?::[a-z0-9]+)?\s+\(([^)]*)\)")
YUM_LINE_RE = re.compile(r"^(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+?):\s*(.*)$")
YUM_INSTALL = {"Installed", "Installed as dep", "Updated", "Upgraded"}
YUM_REMOVE = {"Erased", "Removed", "Downgraded"}
DNF_LINE_RE = re.compile(r"^(\S+) (?:INFO|SUBDEBUG|DEBUG|WARNING|ERROR)\s+(Installed|Upgraded|Removed|Erased):\s*(.*)$")
PACKAGE_MESSAGE_RE = re.compile(r"^package (install|update|remove) (\S+?)(?:\s+(.*))?$")


def parse_package_message(message: str) -> dict | None:
    """Split a canonical package message into action/name/version.

    The architecture suffix (``:amd64``) is stripped from the name so
    detectors match bare tool names.
    """
    match = PACKAGE_MESSAGE_RE.match(message)
    if not match:
        return None
    action, name, version = match.groups()
    return {"action": action, "name": name.split(":")[0], "version": (version or "").strip()}


def _naive_local(evidence: Evidence, year: int, month: int, day: int, hour: int, minute: int, second: int):
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=evidence.tzinfo).astimezone(UTC)
    except (ValueError, OverflowError, OSError):
        return None


def _install_event(evidence, member, display, lineno, line, action, name, version, timestamp) -> Event:
    return Event(
        timestamp_utc=timestamp,
        host=evidence.context.hostname,
        user=None,
        source_artifact="packages",
        event_type=f"package_{action}",
        message=f"package {action} {name} {version}".strip(),
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["packages", action],
        confidence=1.0,
        parser=PARSER_NAME,
        timestamp_quality="tz_assumed",
    )


def _unparsed(evidence: Evidence, member: str, lineno: int, line: str) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=None,
        source_artifact="packages",
        event_type="unparsed",
        message=line.strip()[:500],
        evidence_path=evidence.display_path(member),
        line_or_offset=lineno,
        raw=line,
        tags=["unparsed"],
        confidence=0.1,
        parser=PARSER_NAME,
    )


def _parse_dpkg(evidence, member, display, stats) -> Iterator[Event]:
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text:
            continue
        match = DPKG_LINE_RE.match(text)
        if match is None:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        year, month, day, hour, minute, second, action, name, rest = match.groups()
        if action in DPKG_INSTALL:
            kind = "install"
        elif action in DPKG_REMOVE:
            kind = "remove"
        else:
            continue
        timestamp = _naive_local(
            evidence, int(year), int(month), int(day), int(hour), int(minute), int(second)
        )
        if timestamp is None:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        version = (rest or "").split()[0] if rest else ""
        stats["events"] += 1
        yield _install_event(evidence, member, display, lineno, line, kind, name, version, timestamp)


def _parse_apt_history(evidence, member, display, stats) -> Iterator[Event]:
    timestamp = None
    commandline = ""
    pending: list[tuple[str, str, str]] = []

    def flush(lineno: int, line: str):
        for kind, name, version in pending:
            stats["events"] += 1
            event = _install_event(evidence, member, display, lineno, line, kind, name, version, timestamp)
            if commandline:
                event.message = f"{event.message} via {commandline[:200]}"
            yield event
        pending.clear()

    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text:
            continue
        start = APT_START_RE.match(text)
        if start is not None:
            date, hour, minute, second = start.group(1), *start.groups()[1:]
            year, month, day = (int(part) for part in date.split("-"))
            timestamp = _naive_local(evidence, year, month, day, int(hour), int(minute), int(second))
            commandline = ""
            continue
        cmd = APT_CMD_RE.match(text)
        if cmd is not None:
            commandline = cmd.group(1).strip()
            continue
        if text.startswith("End-Date:"):
            yield from flush(lineno, line)
            timestamp = None
            continue
        pkg = APT_PKG_RE.match(text)
        if pkg is not None and pkg.group(1) in ("Install", "Upgrade", "Remove"):
            kind = "remove" if pkg.group(1) == "Remove" else "install"
            for entry in APT_ENTRY_RE.finditer(pkg.group(2)):
                name, versions = entry.groups()
                version = versions.split(",")[-1].strip()
                pending.append((kind, name, version))
            continue
    yield from flush(0, "")


def _parse_yum(evidence, member, display, stats, tracker) -> Iterator[Event]:
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text:
            continue
        match = YUM_LINE_RE.match(text)
        if match is None:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        month, day, hour, minute, second, action, rest = match.groups()
        if action in YUM_INSTALL:
            kind = "install"
        elif action in YUM_REMOVE:
            kind = "remove"
        else:
            continue
        try:
            timestamp, _quality, _tag = tracker.resolve(month, int(day), int(hour), int(minute), int(second))
        except ValueError:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        name = rest.split(",")[0].strip().split()[0] if rest.strip() else ""
        if not name:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        stats["events"] += 1
        event = _install_event(evidence, member, display, lineno, line, kind, name, "", timestamp)
        event.timestamp_quality = "inferred_year"
        yield event


def _parse_dnf(evidence, member, display, stats) -> Iterator[Event]:
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text:
            continue
        match = DNF_LINE_RE.match(text)
        if match is None:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        stamp, action, rest = match.groups()
        kind = "install" if action in ("Installed", "Upgraded") else "remove"
        try:
            timestamp, _quality = parse_iso8601(stamp)
        except ValueError:
            naive = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})", stamp)
            if naive is None:
                stats["events"] += 1
                stats["unparsed"] += 1
                yield _unparsed(evidence, member, lineno, line)
                continue
            timestamp = _naive_local(evidence, *(int(part) for part in naive.groups()))
            if timestamp is None:
                stats["events"] += 1
                stats["unparsed"] += 1
                yield _unparsed(evidence, member, lineno, line)
                continue
        name = rest.split(",")[0].strip().split()[0] if rest.strip() else ""
        if not name:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        stats["events"] += 1
        yield _install_event(evidence, member, display, lineno, line, kind, name, "", timestamp)


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    name = PurePosixPath(display).name
    if "history.log" in name:
        yield from _parse_apt_history(evidence, member, display, stats)
    elif "yum" in display:
        tracker = SyslogYearTracker(evidence.context.collection_time_utc, evidence.tzinfo, evidence.tz_source)
        yield from _parse_yum(evidence, member, display, stats, tracker)
    elif "dnf" in display:
        yield from _parse_dnf(evidence, member, display, stats)
    else:
        yield from _parse_dpkg(evidence, member, display, stats)
