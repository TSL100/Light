"""Live process snapshot: `ps auxf` output, one undated event per process.

START column values (Jan01, 03:12) are too ambiguous for exact
timestamps, so processes stay undated but keep user, pid and the full
command line for tunnel/backdoor hunting.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..ingest import Evidence
from ..schema import Event

PARSER_NAME = "live_processes"
CONSUMES = ["live_ps"]

PROCESS_MESSAGE_RE = re.compile(r"^process (\S+) pid=(\d+): (.*)$")


def parse_process_message(message: str) -> dict | None:
    """Split a canonical process message into user/pid/command."""
    match = PROCESS_MESSAGE_RE.match(message)
    if not match:
        return None
    return {"user": match.group(1), "pid": int(match.group(2)), "command": match.group(3)}


def _unparsed(evidence: Evidence, member: str, lineno: int, line: str) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=None,
        source_artifact="process",
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
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text or text.startswith("USER"):
            continue
        parts = text.split(None, 10)
        if len(parts) < 11:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        user, pid = parts[0], parts[1]
        if not pid.isdigit():
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        command = parts[10]
        stats["events"] += 1
        yield Event(
            timestamp_utc=None,
            host=evidence.context.hostname,
            user=user,
            source_artifact="process",
            event_type="process",
            message=f"process {user} pid={pid}: {command}",
            evidence_path=display,
            line_or_offset=lineno,
            raw=line,
            tags=["process"],
            confidence=1.0,
            parser=PARSER_NAME,
        )
