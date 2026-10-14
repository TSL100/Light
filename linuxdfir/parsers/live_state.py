"""Live-state snapshot parser: ps, ss, lsof, who, last, lsmod, mount, docker.

Live outputs are a point-in-time snapshot taken when the collector ran, so
every event is dated at the manifest collection time with exact quality
(state as of collection, not an event log). ps auxf keeps the historical
``process <user> pid=<pid>: <command>`` message format (consumed by the
remote-access detector) and adds a ``depth:<n>`` tag derived from the
original indentation so parent/child structure survives; the stderr
separator the collector appends is skipped.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..ingest import Evidence
from ..schema import Event

PARSER_NAME = "live_state"
CONSUMES = ["live_ps", "live_ss", "live_lsof", "live_who", "live_last", "live_lsmod", "live_mount", "live_docker"]

STDERR_SEPARATOR = "<<<STDERR>>>"

PROCESS_MESSAGE_RE = re.compile(r"^process (\S+) pid=(\d+): (.*)$")


def parse_process_message(message: str) -> dict | None:
    """Split a canonical process message into user/pid/command."""
    match = PROCESS_MESSAGE_RE.match(message)
    if not match:
        return None
    return {"user": match.group(1), "pid": int(match.group(2)), "command": match.group(3)}


SS_PROCESS_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


def parse_ss_message(message: str) -> dict | None:
    """Split a canonical ss message into state/local/peer/process."""
    if not message.startswith("ss "):
        return None
    rest = message[3:]
    state = rest.split(None, 1)[0] if rest else ""
    fields = dict(re.findall(r" (\w+)=(\S+)", " " + rest))
    fields["state"] = state
    return fields


def parse_lsof_message(message: str) -> dict | None:
    if not message.startswith("lsof "):
        return None
    return dict(re.findall(r" (\w+)=(\S+)", " " + message[5:]))


def parse_container_message(message: str) -> dict | None:
    """Split a canonical container message into id/image/names/row."""
    if not message.startswith("container "):
        return None
    return dict(re.findall(r" (\w+)=(\S+)", " " + message[10:]))


def _member_kind(member: str) -> str:
    name = member.rsplit("/", 1)[-1]
    return name[: -len(".txt")] if name.endswith(".txt") else name


def _depth(line: str) -> int:
    stripped = line.lstrip(" ")
    return (len(line) - len(stripped)) // 2


def _event(evidence, display, lineno, line, event_type, message, tags, timestamp,
           user=None):
    return Event(
        timestamp_utc=timestamp,
        host=evidence.context.hostname,
        user=user,
        source_artifact="live",
        event_type=event_type,
        message=message,
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=tags,
        confidence=1.0,
        parser=PARSER_NAME,
    )


def _parse_ps(evidence, display, lineno, line, text, timestamp, stats):
    if text.startswith("USER"):
        return None
    parts = text.split(None, 10)
    if len(parts) < 11 or not parts[1].isdigit():
        stats["events"] += 1
        stats["unparsed"] += 1
        return _event(
            evidence, display, lineno, line, "unparsed", text[:500], ["unparsed"], None
        )
    user, pid, command = parts[0], parts[1], parts[10]
    stats["events"] += 1
    return _event(
        evidence,
        display,
        lineno,
        line,
        "process",
        f"process {user} pid={pid}: {command}",
        ["process", f"depth:{_depth(line)}"],
        timestamp,
        user=user,
    )


def _parse_ss(evidence, display, lineno, line, text, timestamp, stats):
    if text.startswith("Netid"):
        return None
    parts = text.split()
    if len(parts) < 6 or not parts[1].isalpha():
        stats["events"] += 1
        stats["unparsed"] += 1
        return _event(
            evidence, display, lineno, line, "unparsed", text[:500], ["unparsed"], None
        )
    netid, state = parts[0], parts[1]
    local, peer = parts[4], parts[5]
    proc_match = SS_PROCESS_RE.search(text)
    process = ""
    if proc_match is not None:
        process = f"{proc_match.group(1)}/{proc_match.group(2)}"
    stats["events"] += 1
    return _event(
        evidence,
        display,
        lineno,
        line,
        "ss_socket",
        f"ss {state} netid={netid} local={local} peer={peer} process={process or '-'}",
        ["network", "ss", state.lower()],
        timestamp,
    )


def _parse_lsof(evidence, display, lineno, line, text, timestamp, stats):
    if text.startswith("COMMAND"):
        return None
    parts = text.split(None, 8)
    if len(parts) < 9 or not parts[1].isdigit():
        stats["events"] += 1
        stats["unparsed"] += 1
        return _event(
            evidence, display, lineno, line, "unparsed", text[:500], ["unparsed"], None
        )
    command, pid, user, fd, name = parts[0], parts[1], parts[2], parts[3], parts[8]
    stats["events"] += 1
    return _event(
        evidence,
        display,
        lineno,
        line,
        "lsof_entry",
        f"lsof command={command} pid={pid} user={user} fd={fd} name={name.replace(' ', '_')}",
        ["network", "lsof"],
        timestamp,
        user=user,
    )


def _parse_who(evidence, display, lineno, line, text, timestamp, stats):
    parts = text.split()
    if len(parts) < 4:
        stats["events"] += 1
        stats["unparsed"] += 1
        return _event(
            evidence, display, lineno, line, "unparsed", text[:500], ["unparsed"], None
        )
    user, tty, date, clock = parts[0], parts[1], parts[2], parts[3]
    host = parts[4].strip("()") if len(parts) > 4 else "-"
    stats["events"] += 1
    return _event(
        evidence,
        display,
        lineno,
        line,
        "who_session",
        f"who user={user} line={tty} when={date}_{clock.replace(':', '')} host={host}",
        ["sessions", "who"],
        timestamp,
        user=user,
    )


def _parse_last(evidence, display, lineno, line, text, timestamp, stats):
    lowered = text.lower()
    if lowered.startswith(("reboot ", "wtmp begins", "wtmp ends", "utmp begins")):
        return None
    parts = text.split()
    if len(parts) < 3:
        stats["events"] += 1
        stats["unparsed"] += 1
        return _event(
            evidence, display, lineno, line, "unparsed", text[:500], ["unparsed"], None
        )
    user, host = parts[0], parts[1]
    rest = "_".join(parts[2:]).replace(":", "")
    stats["events"] += 1
    return _event(
        evidence,
        display,
        lineno,
        line,
        "last_login",
        f"last user={user} host={host} when={rest}",
        ["sessions", "last"],
        timestamp,
        user=user,
    )


def _parse_lsmod(evidence, display, lineno, line, text, timestamp, stats):
    if text.startswith("Module"):
        return None
    parts = text.split()
    if len(parts) < 3:
        stats["events"] += 1
        stats["unparsed"] += 1
        return _event(
            evidence, display, lineno, line, "unparsed", text[:500], ["unparsed"], None
        )
    module, size = parts[0], parts[1]
    used_by = parts[3] if len(parts) > 3 and parts[2] == "-" else parts[2]
    stats["events"] += 1
    return _event(
        evidence,
        display,
        lineno,
        line,
        "loaded_module",
        f"lsmod module={module} size={size} used_by={used_by.replace(',', '-')}",
        ["kernel", "lsmod"],
        timestamp,
    )


def _parse_mount(evidence, display, lineno, line, text, timestamp, stats):
    match = re.match(r"^(\S+) on (\S+) type (\S+) \((.*)\)$", text)
    if match is None:
        if not text.strip():
            return None
        stats["events"] += 1
        stats["unparsed"] += 1
        return _event(
            evidence, display, lineno, line, "unparsed", text[:500], ["unparsed"], None
        )
    source, target, fstype, opts = match.groups()
    stats["events"] += 1
    return _event(
        evidence,
        display,
        lineno,
        line,
        "mount_entry",
        f"mount source={source} target={target} fstype={fstype} opts={opts.replace(' ', '_')}",
        ["filesystem", "mount"],
        timestamp,
    )


def _parse_docker(evidence, display, lineno, line, text, timestamp, stats):
    if text.startswith("CONTAINER ID"):
        return None
    parts = text.split(None, 2)
    if len(parts) < 2:
        stats["events"] += 1
        stats["unparsed"] += 1
        return _event(
            evidence, display, lineno, line, "unparsed", text[:500], ["unparsed"], None
        )
    container_id, image = parts[0], parts[1]
    rest = parts[2] if len(parts) > 2 else ""
    tokens = rest.split()
    names = tokens[-1] if tokens else "-"
    stats["events"] += 1
    return _event(
        evidence,
        display,
        lineno,
        line,
        "container_row",
        f"container id={container_id} image={image} names={names} row={text.replace(' ', '_')}",
        ["containers", "docker"],
        timestamp,
    )


KIND_PARSERS = {
    "ps_auxf": _parse_ps,
    "ss_tulpn": _parse_ss,
    "lsof_nP": _parse_lsof,
    "who": _parse_who,
    "last": _parse_last,
    "lsmod": _parse_lsmod,
    "mount": _parse_mount,
    "docker_ps_a": _parse_docker,
}


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    parser = KIND_PARSERS.get(_member_kind(member))
    timestamp = evidence.context.collection_time_utc
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if text == STDERR_SEPARATOR:
            continue
        if not text:
            continue
        if parser is None:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _event(
                evidence, display, lineno, line, "unparsed", text[:500], ["unparsed"], None
            )
            continue
        event = parser(evidence, display, lineno, line, text, timestamp, stats)
        if event is not None:
            yield event
