"""journald parser: collector's `journalctl --no-pager -o short-iso` export.

Short-iso lines carry an ISO timestamp with offset (exact quality) plus
host, unit/process, optional pid and the message. Journal `-- ... --`
markers and blank lines are skipped; anything else becomes unparsed.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..ingest import Evidence
from ..schema import Event
from ..timeutil import parse_iso8601

PARSER_NAME = "journald"
CONSUMES = ["live_journal"]

JOURNAL_LINE_RE = re.compile(r"^(\S+) (\S+) ([^\[:]+?)(?:\[(\d+)\])?: (.*)$")


def _unparsed(evidence: Evidence, member: str, lineno: int, line: str) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=None,
        source_artifact="journal",
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
        if not text or text.startswith("--"):
            continue
        match = JOURNAL_LINE_RE.match(line)
        if match is None:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        stamp, _host, proc, pid, message = match.groups()
        try:
            timestamp_utc, quality = parse_iso8601(stamp)
        except ValueError:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, lineno, line)
            continue
        stats["events"] += 1
        yield Event(
            timestamp_utc=timestamp_utc,
            host=evidence.context.hostname,
            user=None,
            source_artifact="journal",
            event_type="journal_entry",
            message=f"[{proc}] {message.strip()[:500]}",
            evidence_path=display,
            line_or_offset=lineno,
            raw=line,
            tags=["journal"],
            confidence=1.0,
            parser=PARSER_NAME,
            timestamp_quality=quality,
        )
