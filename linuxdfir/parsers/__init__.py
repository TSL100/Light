"""Parser registry and shared member iteration.

Each parser module exposes PARSER_NAME, CONSUMES (artifact registry keys)
and parse_member(evidence, member, stats=None), a generator yielding Events
one line/record at a time without loading whole files into memory.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..ingest import Evidence
from ..schema import Event, artifacts_for_path

ROTATED_SUFFIX_RE = re.compile(r"\.(\d+)(\.gz)?$")
DATED_SUFFIX_RE = re.compile(r"-(\d{8})(?:\.gz)?$")


def rotation_key(member: str) -> tuple:
    """Sort key ordering rotated logs oldest first, current file last."""
    numbered = ROTATED_SUFFIX_RE.search(member)
    if numbered:
        return (0, -int(numbered.group(1)), member)
    dated = DATED_SUFFIX_RE.search(member)
    if dated:
        return (1, dated.group(1), member)
    return (2, "", member)


def iter_members(evidence: Evidence, consumes: list[str]) -> Iterator[str]:
    """Yield archive members matching any consumed artifact, oldest first."""
    wanted = set(consumes)
    matched = [
        member
        for member in evidence.members
        if wanted & set(artifacts_for_path(original_path=evidence.display_path(member), archive_path=member))
    ]
    matched.sort(key=rotation_key)
    yield from matched


def _register(parsers: dict, module) -> None:
    parsers[module.PARSER_NAME] = module


def available_parsers() -> dict:
    from . import auth_log

    parsers: dict = {}
    _register(parsers, auth_log)
    return parsers


def parse_all(evidence: Evidence, parser_names: list[str] | None = None) -> Iterator[tuple[str, str, Event]]:
    """Yield (parser_name, member, event) across selected parsers."""
    selected = available_parsers()
    if parser_names:
        selected = {name: selected[name] for name in parser_names}
    for name, module in selected.items():
        for member in iter_members(evidence, module.CONSUMES):
            for event in module.parse_member(evidence, member):
                yield name, member, event
