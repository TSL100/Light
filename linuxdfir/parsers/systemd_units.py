"""systemd unit parser: services, timers and sockets.

Extracts Description, User, WantedBy and every ExecStart/ExecStartPre/
ExecStop/ExecReload directive with line numbers, plus Environment lines.
Masked units (manifest records with masked:true) have no file content, so
they are surfaced separately via parse_manifest().
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from ..ingest import Evidence
from ..schema import Event
from . import user_for_path

PARSER_NAME = "systemd_units"
CONSUMES = ["systemd_unit"]

SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
DIRECTIVE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*$")
EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload")
ENV_KEYS = ("Environment", "EnvironmentFile")
MAX_UNIT_BYTES = 1024 * 1024
EXEC_MESSAGE_RE = re.compile(r"^(Exec\w+)=(.+) \(user=(.+)\)$")


def parse_exec_message(message: str) -> dict | None:
    """Split a canonical systemd_exec message into key/value/user."""
    match = EXEC_MESSAGE_RE.match(message)
    if not match:
        return None
    key, value, user = match.groups()
    return {"key": key, "value": value, "user": user}


def _unit_name(display: str) -> str:
    return PurePosixPath(display).name


def _unit_event(evidence, member, display, lineno, line, user, description, wanted_by) -> Event:
    detail = f"unit {_unit_name(display)}"
    if description:
        detail += f": {description}"
    detail += f" (user={user or 'root'}"
    if wanted_by:
        detail += f", wanted-by={','.join(wanted_by)}"
    detail += ")"
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=user or "root",
        source_artifact="systemd_unit",
        event_type="systemd_unit",
        message=detail,
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["persistence", "systemd"],
        confidence=1.0,
        parser=PARSER_NAME,
    )


def _exec_event(evidence, member, display, lineno, line, key, value, user) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=user or "root",
        source_artifact="systemd_unit",
        event_type="systemd_exec",
        message=f"{key}={value} (user={user or 'root'})",
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["persistence", "systemd"],
        confidence=1.0,
        parser=PARSER_NAME,
    )


def _env_event(evidence, member, display, lineno, line, key, value) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=None,
        source_artifact="systemd_unit",
        event_type="systemd_env",
        message=f"{key}={value}",
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["systemd"],
        confidence=1.0,
        parser=PARSER_NAME,
    )


def _unparsed(evidence, member, display, lineno, line) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=user_for_path(display),
        source_artifact="systemd_unit",
        event_type="unparsed",
        message=line.strip()[:500],
        evidence_path=display,
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
    try:
        data = evidence.read_bytes(member)
    except Exception as exc:
        stats["unparsed"] += 1
        yield _unparsed(evidence, member, display, 0, f"<unreadable: {exc}>")
        return
    if len(data) > MAX_UNIT_BYTES:
        stats["unparsed"] += 1
        yield _unparsed(evidence, member, display, 0, "<file too large>")
        return
    text = data.decode("utf-8", errors="replace")
    if "\x00" in text[:4096]:
        stats["events"] += 1
        stats["unparsed"] += 1
        yield _unparsed(evidence, member, display, 1, "<binary file>")
        return
    collected: list[tuple] = []
    has_content = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        stats["lines"] += 1
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        has_content = True
        section = SECTION_RE.match(stripped)
        if section:
            collected.append((lineno, line, "section", section.group(1), ""))
            continue
        directive = DIRECTIVE_RE.match(stripped)
        if directive:
            collected.append((lineno, line, "directive", directive.group(1), directive.group(2)))
            continue
        collected.append((lineno, line, "junk", "", stripped))
    if not has_content:
        return
    user = None
    description = None
    description_line = 1
    description_raw = ""
    wanted_by: list[str] = []
    for lineno, line, kind, key, value in collected:
        if kind == "directive" and key == "User":
            user = value.split()[0] if value.split() else None
        elif kind == "directive" and key == "Description":
            description = value
            description_line = lineno
            description_raw = line
        elif kind == "directive" and key == "WantedBy":
            wanted_by.extend(part.strip() for part in value.split() if part.strip())
    stats["events"] += 1
    yield _unit_event(evidence, member, display, description_line, description_raw, user, description, wanted_by)
    for lineno, line, kind, key, value in collected:
        if kind == "junk":
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, display, lineno, line)
        elif kind == "directive" and key in EXEC_KEYS and value:
            stats["events"] += 1
            yield _exec_event(evidence, member, display, lineno, line, key, value, user)
        elif kind == "directive" and key in ENV_KEYS and value:
            stats["events"] += 1
            yield _env_event(evidence, member, display, lineno, line, key, value)


def parse_manifest(evidence: Evidence, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": "manifest.json", "lines": 0, "events": 0, "unparsed": 0})
    for record in evidence.manifest.get("files", []):
        if not record.get("masked"):
            continue
        original = record.get("original_path", "?")
        stats["events"] += 1
        yield Event(
            timestamp_utc=None,
            host=evidence.context.hostname,
            user=None,
            source_artifact="systemd_unit",
            event_type="systemd_masked",
            message=f"masked unit {original} -> {record.get('symlink_target')}",
            evidence_path=original,
            line_or_offset=None,
            raw=f"{original} -> {record.get('symlink_target')}",
            tags=["persistence", "systemd", "masked"],
            confidence=1.0,
            parser=PARSER_NAME,
        )
