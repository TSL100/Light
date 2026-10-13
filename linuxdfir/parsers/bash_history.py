"""Shell and editor history parser: bash/zsh/python history plus viminfo.

Handles `#<epoch>` timestamp lines (HISTTIMEFORMAT) and zsh extended
history (`: <epoch>:<duration>;<command>`). Lines without timestamps yield
undated events ordered by line number. Command text is preserved verbatim;
attacker-controlled content is never interpreted.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime

from ..ingest import Evidence
from ..schema import Event
from . import user_for_path

PARSER_NAME = "bash_history"
CONSUMES = ["bash_history", "zsh_history", "viminfo", "python_history"]

EPOCH_LINE_RE = re.compile(r"^#(\d+)\s*$")
ZSH_EXTENDED_RE = re.compile(r"^:\s*(\d+):\d+;(.*)$")
VIM_CMDLINE_RE = re.compile(r"^:(.+)$")
VIM_SEARCH_RE = re.compile(r"^[/?](.+)$")
VIM_META_RE = re.compile(r"^[#\"|].*$")


def _event(
    evidence: Evidence,
    member: str,
    lineno: int,
    user: str | None,
    event_type: str,
    command: str,
    timestamp=None,
    quality: str = "none",
) -> Event:
    return Event(
        timestamp_utc=timestamp,
        host=evidence.context.hostname,
        user=user,
        source_artifact="bash_history",
        event_type=event_type,
        message=command,
        evidence_path=evidence.display_path(member),
        line_or_offset=lineno,
        raw=command,
        tags=["history"],
        confidence=1.0,
        parser=PARSER_NAME,
        timestamp_quality=quality,
    )


def _epoch_to_utc(value: int):
    return datetime.fromtimestamp(value, tz=UTC)


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    user = user_for_path(evidence.display_path(member))
    is_viminfo = evidence.display_path(member).endswith("viminfo")
    pending_ts = None
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text:
            continue
        timestamp = None
        quality = "none"
        event_type = "shell_command"
        epoch_match = EPOCH_LINE_RE.match(text)
        if epoch_match:
            try:
                pending_ts = _epoch_to_utc(int(epoch_match.group(1)))
            except (ValueError, OverflowError, OSError):
                pending_ts = None
            continue
        zsh_match = ZSH_EXTENDED_RE.match(text)
        if zsh_match:
            try:
                timestamp = _epoch_to_utc(int(zsh_match.group(1)))
                quality = "exact"
            except (ValueError, OverflowError, OSError):
                timestamp = None
            text = zsh_match.group(2)
        elif is_viminfo and text.startswith(":"):
            cmdline = VIM_CMDLINE_RE.match(text)
            if cmdline:
                event_type = "vim_command"
                text = cmdline.group(1)
            else:
                continue
        elif is_viminfo and text.startswith(("/", "?")):
            search = VIM_SEARCH_RE.match(text)
            if search:
                event_type = "vim_search"
                text = search.group(1)
            else:
                continue
        elif is_viminfo and VIM_META_RE.match(text):
            continue
        elif pending_ts is not None:
            timestamp = pending_ts
            quality = "exact"
            pending_ts = None
        else:
            pending_ts = None
        stats["events"] += 1
        yield _event(evidence, member, lineno, user, event_type, text, timestamp, quality)
