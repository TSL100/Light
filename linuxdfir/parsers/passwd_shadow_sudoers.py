"""Accounts parser: passwd, shadow (states only), group, sudoers.

Shadow password hashes are NEVER kept: only the account state
(locked / no-login / empty / has-password) is recorded.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from ..ingest import Evidence
from ..schema import Event

PARSER_NAME = "passwd_shadow_sudoers"
CONSUMES = ["passwd", "shadow", "group", "sudoers"]

NOLOGIN_SHELLS = ("nologin", "false")
NOPASSWD_RE = re.compile(r"\bNOPASSWD\b|!authenticate\b")
ACCOUNT_MESSAGE_RE = re.compile(
    r"^account (\S+): uid=(\d+) gid=(\d+) shell=(.*?) home=(.*?) \[(no-shell|interactive-shell)\]$"
)


def parse_account_message(message: str) -> dict | None:
    """Split a canonical user_account message back into its fields."""
    match = ACCOUNT_MESSAGE_RE.match(message)
    if not match:
        return None
    name, uid, gid, shell, home, note = match.groups()
    return {
        "name": name,
        "uid": int(uid),
        "gid": int(gid),
        "shell": "" if shell == "(none)" else shell,
        "home": "" if home == "(none)" else home,
        "interactive": note == "interactive-shell",
    }


def _kind_for_member(display: str) -> str:
    name = PurePosixPath(display).name
    if name == "passwd":
        return "passwd"
    if name == "shadow":
        return "shadow"
    if name == "group":
        return "group"
    return "sudoers"


def _base(evidence, member, display, lineno, line, artifact, event_type, user, message, tags, confidence=1.0) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=user,
        source_artifact=artifact,
        event_type=event_type,
        message=message,
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=tags,
        confidence=confidence,
        parser=PARSER_NAME,
    )


def _shadow_state(entry: str) -> str:
    if entry == "" or entry == "x":
        return "empty"
    if entry == "*" or entry == "!*":
        return "no-login"
    if entry.startswith("!"):
        return "locked"
    return "has-password"


def _parse_passwd_line(fields: list[str]) -> dict | None:
    if len(fields) != 7:
        return None
    name, _pw, uid, gid, _gecos, home, shell = fields
    if not name or not uid.isdigit() or not gid.isdigit():
        return None
    return {"name": name, "uid": int(uid), "gid": int(gid), "home": home, "shell": shell}


def _interactive_shell(shell: str) -> bool:
    base = shell.rsplit("/", 1)[-1].strip()
    return bool(base) and base not in NOLOGIN_SHELLS


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    kind = _kind_for_member(display)
    pending = ""
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text:
            continue
        if kind == "sudoers":
            if text.startswith("#"):
                continue
            if text.endswith("\\"):
                pending += text[:-1] + " "
                continue
            if pending:
                text = pending + text
                pending = ""
            event = _parse_sudoers_line(evidence, member, display, lineno, line, text)
        elif kind == "passwd":
            if text.startswith("#"):
                continue
            account = _parse_passwd_line(text.split(":"))
            if account is None:
                event = _unparsed(evidence, member, display, lineno, line, kind)
                stats["unparsed"] += 1
            else:
                shell_note = "interactive-shell" if _interactive_shell(account["shell"]) else "no-shell"
                event = _base(
                    evidence, member, display, lineno, line, kind, "user_account", account["name"],
                    f"account {account['name']}: uid={account['uid']} gid={account['gid']} "
                    f"shell={account['shell'] or '(none)'} home={account['home'] or '(none)'} [{shell_note}]",
                    ["account"],
                )
        elif kind == "shadow":
            fields = text.split(":")
            if len(fields) < 2 or not fields[0]:
                event = _unparsed(evidence, member, display, lineno, line, kind)
                stats["unparsed"] += 1
            else:
                state = _shadow_state(fields[1])
                event = _base(
                    evidence, member, display, lineno, line, kind, "shadow_state", fields[0],
                    f"account {fields[0]}: {state}",
                    ["account"],
                )
        else:
            fields = text.split(":")
            if text.startswith("#"):
                continue
            if len(fields) < 3 or not fields[0]:
                event = _unparsed(evidence, member, display, lineno, line, kind)
                stats["unparsed"] += 1
            else:
                try:
                    gid = int(fields[2])
                except ValueError:
                    event = _unparsed(evidence, member, display, lineno, line, kind)
                    stats["unparsed"] += 1
                else:
                    members = fields[3] if len(fields) > 3 else ""
                    event = _base(
                        evidence, member, display, lineno, line, kind, "group_entry", None,
                        f"group {fields[0]}: gid={gid} members=[{members}]",
                        ["account"],
                    )
        stats["events"] += 1
        yield event


def _parse_sudoers_line(evidence, member, display, lineno, line, text) -> Event:
    stripped = text.strip()
    first_token = stripped.split(None, 1)[0] if stripped.split(None, 1) else ""
    if stripped.startswith(("#", "Defaults", "@include", "#include")) or "=" in first_token:
        return _base(
            evidence, member, display, lineno, line, "sudoers", "sudoers_directive", None,
            f"sudoers: {stripped[:300]}",
            ["sudo"],
        )
    parts = stripped.split(None, 1)
    if len(parts) != 2:
        return _unparsed(evidence, member, display, lineno, line, "sudoers")
    who, rest = parts
    if who in ("User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias"):
        return _base(
            evidence, member, display, lineno, line, "sudoers", "sudoers_directive", None,
            f"sudoers: {stripped[:300]}",
            ["sudo"],
        )
    nopasswd = bool(NOPASSWD_RE.search(rest))
    tags = ["sudo", "sudoers"]
    if who.startswith("%"):
        tags.append("sudo_group")
    if nopasswd:
        tags.append("nopasswd")
    return _base(
        evidence, member, display, lineno, line, "sudoers", "sudo_rule", who.lstrip("%"),
        f"sudo: {who} {rest.strip()[:300]}",
        tags,
    )


def _unparsed(evidence, member, display, lineno, line, artifact) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=None,
        source_artifact=artifact,
        event_type="unparsed",
        message=line.strip()[:500],
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["unparsed"],
        confidence=0.1,
        parser=PARSER_NAME,
    )
