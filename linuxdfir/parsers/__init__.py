"""Parser registry and shared member iteration.

Each parser module exposes PARSER_NAME, CONSUMES (artifact registry keys)
and parse_member(evidence, member, stats=None), a generator yielding Events
one line/record at a time without loading whole files into memory.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..ingest import Evidence
from ..schema import NON_EVENT_SOURCES, Event, artifacts_for_path

HOME_USER_RE = re.compile(r"^/home/([^/]+)/")


def user_for_path(original_path: str | None) -> str | None:
    """Best-effort owner account for a per-user artifact path."""
    if not original_path:
        return None
    if original_path == "/root" or original_path.startswith("/root/"):
        return "root"
    match = HOME_USER_RE.match(original_path)
    if match:
        return match.group(1)
    return None

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


def skipped_members(evidence: Evidence) -> list[str]:
    """Archive members that are collected but not event sources (never parsed)."""
    seen: list[str] = []
    for key in sorted(NON_EVENT_SOURCES):
        for member in iter_members(evidence, [key]):
            if member not in seen:
                seen.append(member)
    return seen


def _register(parsers: dict, module) -> None:
    parsers[module.PARSER_NAME] = module


PARSER_MODULES = (
    "auth_log",
    "auditd",
    "bash_history",
    "cron",
    "filesystem_suspicious",
    "journald",
    "ld_preload",
    "live_state",
    "package_logs",
    "passwd_shadow_sudoers",
    "profile_scripts",
    "ssh",
    "syslog_kern",
    "systemd_units",
    "web_logs",
    "wtmp_btmp_lastlog",
)


def available_parsers() -> dict:
    import importlib

    parsers: dict = {}
    for name in PARSER_MODULES:
        _register(parsers, importlib.import_module(f"{__name__}.{name}"))
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
