"""Login-shell startup scripts: /etc/profile.d, .bashrc, .profile, .bash_profile.

One undated event per non-blank, non-comment line with its line number, so
backdoored startup files stay traceable to the exact line.
"""

from __future__ import annotations

from collections.abc import Iterator

from ..ingest import Evidence
from ..schema import Event
from . import user_for_path

PARSER_NAME = "profile_scripts"
CONSUMES = ["profile_scripts"]


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    user = user_for_path(display)
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        stats["events"] += 1
        yield Event(
            timestamp_utc=None,
            host=evidence.context.hostname,
            user=user,
            source_artifact="profile_scripts",
            event_type="startup_line",
            message=text,
            evidence_path=display,
            line_or_offset=lineno,
            raw=line,
            tags=["persistence", "startup"],
            confidence=1.0,
            parser=PARSER_NAME,
        )
