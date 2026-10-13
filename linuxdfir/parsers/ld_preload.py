"""ld.so.preload parser: one event per preloaded library (undated)."""

from __future__ import annotations

from collections.abc import Iterator

from ..ingest import Evidence
from ..schema import Event

PARSER_NAME = "ld_preload"
CONSUMES = ["ld_preload"]


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        stats["events"] += 1
        yield Event(
            timestamp_utc=None,
            host=evidence.context.hostname,
            user=None,
            source_artifact="ld_preload",
            event_type="preload_entry",
            message=f"LD_PRELOAD library: {text}",
            evidence_path=display,
            line_or_offset=lineno,
            raw=line,
            tags=["persistence", "preload"],
            confidence=1.0,
            parser=PARSER_NAME,
        )
