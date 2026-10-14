"""Collector triage listings: SUID/SGID, hidden files, recent files, tmp areas.

Each ``triage/*.txt`` TSV becomes one event per row carrying mode, uid/gid,
size and mtime/ctime/atime so detectors can reason about scratch-space
executables, timestomping, unusual SUID binaries and sensitive-path
changes. Files under /tmp, /var/tmp and /dev/shm get an ``elf`` tag when
the archived content starts with the ELF magic (content is only present
when the collector copied the file itself). Messages are canonical
``kind k=v ... path=<path>`` strings parsed back by
:func:`parse_fs_message`.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime

from ..ingest import Evidence
from ..schema import Event

PARSER_NAME = "filesystem_suspicious"
CONSUMES = ["suid_sgid", "hidden_files", "recent_files", "tmp_listing", "var_tmp_listing", "dev_shm_listing"]

ELF_MAGIC = b"\x7fELF"

LIST_KINDS = {
    "suid_sgid": ("suid_sgid_file", "suid"),
    "hidden_files": ("hidden_file", "hidden"),
    "recent_files": ("recent_file", "recent"),
    "tmp_listing": ("tmp_area_file", "tmp-area"),
    "var_tmp_listing": ("tmp_area_file", "tmp-area"),
    "dev_shm_listing": ("tmp_area_file", "tmp-area"),
}

SCRATCH_AREAS = {
    "tmp_listing": "/tmp",
    "var_tmp_listing": "/var/tmp",
    "dev_shm_listing": "/dev/shm",
}

DEFAULT_COLUMNS = {
    "suid_sgid": ["path", "mode", "uid", "gid", "size", "mtime_utc", "flags", "type"],
    "hidden_files": ["path", "type", "mode", "uid", "gid", "size", "mtime_utc"],
    "recent_files": [
        "path", "type", "mode", "uid", "gid", "size", "mtime_utc", "ctime_utc", "atime_utc",
    ],
    "tmp_listing": [
        "path", "type", "mode", "uid", "gid", "size", "mtime_utc", "ctime_utc", "atime_utc",
    ],
    "var_tmp_listing": [
        "path", "type", "mode", "uid", "gid", "size", "mtime_utc", "ctime_utc", "atime_utc",
    ],
    "dev_shm_listing": [
        "path", "type", "mode", "uid", "gid", "size", "mtime_utc", "ctime_utc", "atime_utc",
    ],
}

FS_MESSAGE_RE = re.compile(r"^(?P<kind>\S+)(?P<fields>(?: \S+=\S+)*) path=(?P<path>.*)$")
FS_FIELD_RE = re.compile(r" (\w+)=(\S+)")

def parse_fs_message(message: str) -> dict | None:
    """Split a canonical filesystem-suspicious message into fields + path."""
    match = FS_MESSAGE_RE.match(message)
    if not match:
        return None
    fields = dict(FS_FIELD_RE.findall(match.group("fields") or ""))
    fields["kind"] = match.group("kind")
    fields["path"] = match.group("path")
    return fields


def parse_iso(value: str | None) -> datetime | None:
    """Parse a collector ``%Y-%m-%dT%H:%M:%SZ`` stamp to an aware datetime."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=UTC)
    except ValueError:
        return None


def _elf_member(evidence: Evidence, path: str) -> bool:
    """True when the archived content for an original path is ELF."""
    try:
        return evidence.read_bytes(f"evidence{path}")[:4] == ELF_MAGIC
    except Exception:
        return False


def _list_kind(member: str) -> str:
    name = member.rsplit("/", 1)[-1]
    if name.endswith(".txt"):
        name = name[: -len(".txt")]
    return name if name in LIST_KINDS else "recent_files"


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    kind = _list_kind(member)
    event_type, kind_label = LIST_KINDS.get(kind, ("recent_file", "recent"))
    area = SCRATCH_AREAS.get(kind)
    header: list[str] | None = None
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.rstrip("\n")
        if not text.strip():
            continue
        columns = text.split("\t")
        if header is None:
            if columns[0] == "path":
                header = columns
                continue
            header = DEFAULT_COLUMNS[kind]
        if columns[0] == "path" or len(columns) < 2:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, display, lineno, line, text)
            continue
        names = header if len(header) == len(columns) else DEFAULT_COLUMNS[kind]
        if len(names) != len(columns):
            names = ["path"] + [f"col{i}" for i in range(1, len(columns))]
        fields = dict(zip(names, columns, strict=False))
        path = fields.pop("path", "")
        tags = ["triage", kind_label]
        if area is not None and event_type == "tmp_area_file" and _elf_member(evidence, path):
            tags.append("elf")
        kv = " ".join(f"{name}={value.replace(' ', '_')}" for name, value in fields.items())
        stats["events"] += 1
        yield Event(
            timestamp_utc=parse_iso(fields.get("mtime_utc")),
            host=evidence.context.hostname,
            user=None,
            source_artifact="filesystem",
            event_type=event_type,
            message=f"{kind_label} {kv} path={path}",
            evidence_path=display,
            line_or_offset=lineno,
            raw=line,
            tags=tags,
            confidence=1.0,
            parser=PARSER_NAME,
        )


def _unparsed(evidence: Evidence, display: str, lineno: int, line: str, text: str) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=None,
        source_artifact="filesystem",
        event_type="unparsed",
        message=text.strip()[:500],
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["unparsed"],
        confidence=0.1,
        parser=PARSER_NAME,
    )
