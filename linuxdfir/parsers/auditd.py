"""auditd parser: type=... msg=audit(epoch.ms:serial) records.

Consecutive records sharing a serial belong to one audit event, so lines
are grouped by serial into a single audit_event plus focused events:
audit_exec (EXECVE with hex-decoded argv and proctitle), audit_auth
(login/auth records), audit_account (user/group management) and
audit_config (config/daemon changes). Epoch timestamps are exact.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from datetime import UTC, datetime

from ..ingest import Evidence
from ..schema import Event

PARSER_NAME = "auditd"
CONSUMES = ["auditd"]

AUDIT_LINE_RE = re.compile(r"^type=(\S+)\s+msg=audit\((\d+)\.(\d+):(\d+)\):\s?(.*)$")
EXECVE_KEYS = re.compile(r"^a\d+$")
HEX_VALUE_RE = re.compile(r"^[0-9a-fA-F]+$")
AUDIT_EXEC_MESSAGE_RE = re.compile(r"^audit exec pid=(\d+) auid=(\S+?): (.*)$")

AUTH_TYPES = {
    "USER_LOGIN", "USER_AUTH", "USER_ACCT", "USER_START", "USER_END",
    "CRED_ACQ", "CRED_DISP", "CRED_REFR", "LOGIN",
}
ACCOUNT_TYPES = {
    "ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "USER_MGMT",
    "GRP_MGMT", "USER_CHAUTHTOK",
}
CONFIG_TYPES = {"CONFIG_CHANGE", "DAEMON_START", "DAEMON_END", "DAEMON_ABORT"}


def parse_audit_exec_message(message: str) -> dict | None:
    """Split a canonical audit_exec message into pid/auid/argv."""
    match = AUDIT_EXEC_MESSAGE_RE.match(message)
    if not match:
        return None
    return {"pid": match.group(1), "auid": match.group(2), "argv": match.group(3)}


def _decode_value(key: str, value: str) -> str:
    if (
        (EXECVE_KEYS.match(key) or key == "proctitle")
        and HEX_VALUE_RE.match(value)
        and len(value) % 2 == 0
        and len(value) >= 2
    ):
        try:
            return bytes.fromhex(value).decode("utf-8", errors="replace")
        except ValueError:
            return value
    return value


def _parse_fields(rest: str) -> dict:
    try:
        tokens = shlex.split(rest, posix=True)
    except ValueError:
        tokens = rest.split()
    fields: dict[str, str] = {}
    for token in tokens:
        key, sep, value = token.partition("=")
        if sep:
            fields[key] = _decode_value(key, value)
    return fields


def _record(line: str) -> dict | None:
    match = AUDIT_LINE_RE.match(line.strip())
    if not match:
        return None
    kind, sec, ms, serial, rest = match.groups()
    try:
        timestamp = datetime.fromtimestamp(int(sec) + int(ms) / 1000.0, tz=UTC)
    except (ValueError, OverflowError, OSError):
        return None
    return {"type": kind, "serial": serial, "timestamp": timestamp, "fields": _parse_fields(rest)}


def _base(evidence, member, display, event_type, user, message, timestamp, tags) -> Event:
    return Event(
        timestamp_utc=timestamp,
        host=evidence.context.hostname,
        user=user,
        source_artifact="auditd",
        event_type=event_type,
        message=message,
        evidence_path=display,
        line_or_offset=None,
        raw="",
        tags=tags,
        confidence=1.0,
        parser=PARSER_NAME,
    )


def _emit_group(evidence, member, display, serial, records, stats) -> Iterator[Event]:
    types = [rec["type"] for rec in records]
    by_type = {}
    for rec in records:
        by_type.setdefault(rec["type"], rec)
    primary = by_type.get("SYSCALL", records[0])
    fields = primary["fields"]
    timestamp = records[0]["timestamp"]
    summary = " ".join(f"{key}={fields[key]}" for key in ("exe", "comm", "auid", "uid", "success") if key in fields)
    stats["events"] += 1
    group = _base(
        evidence, member, display, "audit_event", None,
        f"audit event {serial} [{', '.join(types)}]: {summary or primary['type']}".strip(),
        timestamp, ["audit"],
    )
    group.line_or_offset = 0
    group.raw = "\n".join(rec.get("raw", "") for rec in records)
    yield group
    if "EXECVE" in by_type:
        exec_fields = by_type["EXECVE"]["fields"]
        argc = int(exec_fields.get("argc", "0") or "0")
        argv = [exec_fields.get(f"a{i}", "") for i in range(min(argc, 64))]
        pid = (by_type.get("SYSCALL") or {}).get("fields", {}).get("pid", "?")
        auid = (by_type.get("SYSCALL") or {}).get("fields", {}).get("auid", "?")
        stats["events"] += 1
        item = _base(
            evidence, member, display, "audit_exec", None,
            f"audit exec pid={pid} auid={auid}: {' '.join(argv)}".strip(),
            timestamp, ["audit", "exec"],
        )
        yield item
    for kind, event_type, tag in (
        (AUTH_TYPES, "audit_auth", "auth"),
        (ACCOUNT_TYPES, "audit_account", "account"),
        (CONFIG_TYPES, "audit_config", "config"),
    ):
        for rec in records:
            if rec["type"] in kind:
                fields = rec["fields"]
                user = (fields.get("acct") or fields.get("auid") or "").strip('"') or None
                stats["events"] += 1
                yield _base(
                    evidence, member, display, event_type, user,
                    f"audit {rec['type'].lower()}: "
                    + " ".join(f"{k}={v}" for k, v in list(fields.items())[:8]),
                    timestamp, ["audit", tag],
                )


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    pending_serial: str | None = None
    pending: list[dict] = []

    def flush():
        if pending:
            yield from _emit_group(evidence, member, display, pending_serial, pending, stats)

    for _lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        if not line.strip():
            continue
        rec = _record(line)
        if rec is None:
            stats["unparsed"] += 1
            continue
        rec["raw"] = line
        if pending_serial is not None and rec["serial"] != pending_serial:
            yield from flush()
            pending = []
        pending_serial = rec["serial"]
        pending.append(rec)
    yield from flush()
