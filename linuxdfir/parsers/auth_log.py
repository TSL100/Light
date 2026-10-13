"""auth.log / secure parser: SSH, sudo, session, account and cron events.

Consumes auth_log registry artifacts (auth.log*, secure*, plain or gzipped,
any rotation suffix). Streams line by line; malformed lines become
low-confidence ``unparsed`` events, never exceptions.

User names and commands in logs are attacker-controlled: they are kept as
raw strings, never interpreted. ``message repeated N times`` lines bump
``repeat_count`` on the previous event instead of emitting new events.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

from ..ingest import Evidence
from ..schema import Event
from ..timeutil import SyslogYearTracker, parse_iso8601, parse_syslog_prefix

PARSER_NAME = "auth_log"
CONSUMES = ["auth_log"]

FAILURE_RE = re.compile(r"^Failed (\S+) for (invalid user )?(.+) from (\S+) port (\d+)")
SUCCESS_RE = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)")
INVALID_USER_RE = re.compile(r"^Invalid user (.+) from (\S+)(?: port (\d+))?")
DISCONNECT_USER_RE = re.compile(
    r"^Disconnected from (invalid user|authenticating user|user) (\S+) (\S+) port (\d+)"
)
RECEIVED_DISCONNECT_RE = re.compile(r"^Received disconnect from (\S+) port (\d+)")
CONNECTION_CLOSED_RE = re.compile(r"^Connection (?:closed|reset) by (\S+)(?: port (\d+))?")
SUDO_COMMAND_RE = re.compile(r"^\s*(\S+) : TTY=(\S+) ; PWD=([^;]*) ; USER=(\S+) ; COMMAND=(.+)$")
PAM_SESSION_RE = re.compile(
    r"^pam_unix\(([^:)]+):session\): session (opened|closed) for user ([^\s(]+)(?:\(uid=[^)]*\))?"
)
PAM_AUTH_FAIL_RE = re.compile(r"^pam_unix\(([^:)]+):auth\): authentication failure")
PAM_ERROR_RE = re.compile(
    r"^(?:PAM\b|pam_unix\([^)]*\):)\s*(.*(?:unable|cannot|failed|failure|denied|error|missing).*)$",
    re.IGNORECASE,
)
SHUTDOWN_PROCS = ("systemd-logind", "systemd", "shutdown", "reboot", "init", "systemd-shutdown")
REBOOT_RE = re.compile(r"\breboot", re.IGNORECASE)
SHUTDOWN_RE = re.compile(r"power\s?off|shutting down|\bhalt\b|going down", re.IGNORECASE)
CRON_CMD_RE = re.compile(r"^\(([^)]+)\) CMD \((.*)\)$")
USERADD_RE = re.compile(r"new user: name=([^,\s]+)")
GROUPADD_RE = re.compile(r"new group: name=([^,\s]+)")
PASSWD_RE = re.compile(r"password for '([^']+)' changed")
QUOTED_NAME_RE = re.compile(r"'([^']+)'")
RHOST_RE = re.compile(r"rhost=(\S+)")
RUSER_RE = re.compile(r"\bruser=(\S+)")
AUTH_USER_RE = re.compile(r"\buser=(\S+)")
REPEAT_RE = re.compile(r"^(?:last message repeated|message repeated) (\d+) times?$")
ISO_LINE_RE = re.compile(r"^(\S+) (\S+) ([^\[:]+?)(?:\[(\d+)\])?: (.*)$")


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_ssh_failure(message: str) -> dict | None:
    """Split a canonical failure message into method/user/ip/port."""
    match = FAILURE_RE.match(message)
    if not match:
        return None
    method, _invalid, user, ip, port = match.groups()
    if not _valid_ip(ip):
        return None
    return {"method": method, "user": user, "ip": ip, "port": int(port)}


def extract_ssh_success(message: str) -> dict | None:
    """Split a canonical success message into method/user/ip/port."""
    match = SUCCESS_RE.match(message)
    if not match:
        return None
    method, user, ip, port = match.groups()
    if not _valid_ip(ip):
        return None
    return {"method": method, "user": user, "ip": ip, "port": int(port)}


def _unparsed(evidence: Evidence, member: str, lineno: int, line: str) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=None,
        source_artifact="auth_log",
        event_type="unparsed",
        message=line.strip()[:500],
        evidence_path=evidence.display_path(member),
        line_or_offset=lineno,
        raw=line,
        tags=["unparsed"],
        confidence=0.1,
        parser=PARSER_NAME,
    )


def _match_repeat(line: str) -> int | None:
    prefix = parse_syslog_prefix(line)
    candidate = prefix["message"].strip() if prefix else line.strip()
    match = REPEAT_RE.match(candidate)
    if match:
        return int(match.group(1))
    return None


def _classify(
    message: str, proc: str, pid: int | None, timestamp_utc, quality: str, tz_tag: str | None
) -> tuple[str, str | None, str, list[str], float]:
    tags = [tz_tag] if tz_tag else []
    if proc == "sudo":
        match = SUDO_COMMAND_RE.match(message)
        if match:
            user, tty, pwd, target, command = match.groups()
            return (
                "sudo_command",
                user,
                f"sudo: {user} on {tty} as {target}: {command.strip()}",
                tags + ["sudo"],
                1.0,
            )
        if "NOT in sudoers" in message or "authentication failure" in message:
            who = None
            for pattern in (RUSER_RE, AUTH_USER_RE):
                found = pattern.search(message)
                if found:
                    who = found.group(1)
                    break
            if who is None and ":" in message:
                who = message.split(":", 1)[0].strip().split()[0]
            return (
                "sudo_auth_failure",
                who,
                f"sudo authentication failure for {who}: {message.strip()[:300]}",
                tags + ["sudo"],
                0.9,
            )
    pam = PAM_SESSION_RE.match(message)
    if pam:
        service, action, user = pam.groups()
        if service == "su":
            return (
                "su_session",
                user,
                f"su session {action} for {user}",
                tags + ["session", "su", f"session_{action}"],
                1.0,
            )
        return (
            f"session_{action}",
            user,
            f"{service} session {action} for {user}",
            tags + ["session", service],
            1.0,
        )
    if proc == "CRON" or message.startswith("("):
        cron = CRON_CMD_RE.match(message)
        if cron:
            user, command = cron.groups()
            return (
                "cron_command",
                user,
                f"cron ({user}): {command.strip()}",
                tags + ["cron"],
                1.0,
            )
    if proc in SHUTDOWN_PROCS:
        if REBOOT_RE.search(message):
            return (
                "system_reboot",
                None,
                f"system reboot: {message.strip()[:300]}",
                tags + ["system"],
                1.0,
            )
        if SHUTDOWN_RE.search(message):
            return (
                "system_shutdown",
                None,
                f"system shutdown: {message.strip()[:300]}",
                tags + ["system"],
                1.0,
            )
    failure = FAILURE_RE.match(message)
    if failure:
        method, invalid, user, ip, port = failure.groups()
        marker = invalid or ""
        return (
            "ssh_failed_login",
            user,
            f"Failed {method} for {marker}{user} from {ip} port {port}",
            tags + ["ssh", "auth", "failure"],
            1.0,
        )
    success = SUCCESS_RE.match(message)
    if success:
        method, user, ip, port = success.groups()
        return (
            "ssh_accepted_login",
            user,
            f"Accepted {method} for {user} from {ip} port {port}",
            tags + ["ssh", "auth", "success"],
            1.0,
        )
    invalid = INVALID_USER_RE.match(message)
    if invalid:
        user, ip, port = invalid.groups()
        detail = f" from {ip}" + (f" port {port}" if port else "")
        return (
            "ssh_invalid_user",
            user,
            f"Invalid user {user}{detail}",
            tags + ["ssh", "auth", "failure"],
            1.0,
        )
    disconnect = DISCONNECT_USER_RE.match(message)
    if disconnect:
        _, user, ip, port = disconnect.groups()
        return (
            "ssh_disconnect",
            user,
            f"Disconnected {user} {ip} port {port}",
            tags + ["ssh"],
            0.9,
        )
    received = RECEIVED_DISCONNECT_RE.match(message)
    if received:
        ip, port = received.groups()
        return (
            "ssh_disconnect",
            None,
            f"Received disconnect from {ip} port {port}",
            tags + ["ssh"],
            0.9,
        )
    closed = CONNECTION_CLOSED_RE.match(message)
    if closed:
        ip, port = closed.groups()
        detail = f" port {port}" if port else ""
        return (
            "ssh_disconnect",
            None,
            f"Connection closed by {ip}{detail}",
            tags + ["ssh"],
            0.9,
        )
    pam_fail = PAM_AUTH_FAIL_RE.match(message)
    if pam_fail:
        rhost = RHOST_RE.search(message)
        account = AUTH_USER_RE.search(message)
        if rhost and account:
            ip, user = rhost.group(1), account.group(1)
            return (
                "ssh_failed_login",
                user,
                f"Failed unknown for {user} from {ip}",
                tags + ["ssh", "auth", "failure"],
                0.7,
            )
    pam_error = PAM_ERROR_RE.match(message)
    if pam_error:
        return (
            "pam_error",
            None,
            f"pam: {pam_error.group(1).strip()[:300]}",
            tags + ["pam", "error"],
            0.8,
        )
    useradd = USERADD_RE.search(message)
    if useradd:
        return (
            "useradd",
            useradd.group(1),
            f"new user {useradd.group(1)}: {message.strip()[:300]}",
            tags + ["account"],
            1.0,
        )
    groupadd = GROUPADD_RE.search(message)
    if groupadd:
        return (
            "groupadd",
            None,
            f"new group {groupadd.group(1)}: {message.strip()[:300]}",
            tags + ["account"],
            1.0,
        )
    passwd = PASSWD_RE.search(message)
    if passwd:
        return (
            "passwd",
            passwd.group(1),
            f"password changed for {passwd.group(1)}",
            tags + ["account"],
            1.0,
        )
    if proc == "usermod":
        quoted = QUOTED_NAME_RE.search(message)
        return (
            "usermod",
            quoted.group(1) if quoted else None,
            f"usermod: {message.strip()[:300]}",
            tags + ["account"],
            1.0,
        )
    return None


def _parse_iso_line(
    line: str, lineno: int, member: str, evidence: Evidence
) -> Event:
    match = ISO_LINE_RE.match(line)
    if not match:
        return _unparsed(evidence, member, lineno, line)
    stamp, _host, proc, pid, message = match.groups()
    try:
        timestamp_utc, quality = parse_iso8601(stamp)
    except ValueError:
        return _unparsed(evidence, member, lineno, line)
    return _build_event(
        evidence, member, lineno, line, proc, int(pid) if pid else None, message, timestamp_utc, quality, None
    )


def _build_event(
    evidence: Evidence,
    member: str,
    lineno: int,
    line: str,
    proc: str,
    pid: int | None,
    message: str,
    timestamp_utc,
    quality: str,
    tz_tag: str,
) -> Event:
    classified = _classify(message, proc, pid, timestamp_utc, quality, tz_tag)
    if classified is None:
        event = _unparsed(evidence, member, lineno, line)
        event.timestamp_utc = timestamp_utc
        event.timestamp_quality = quality
        event.tags = ["unparsed"] + ([tz_tag] if tz_tag else [])
        return event
    event_type, user, text, tags, confidence = classified
    return Event(
        timestamp_utc=timestamp_utc,
        host=evidence.context.hostname,
        user=user,
        source_artifact="auth_log",
        event_type=event_type,
        message=text,
        evidence_path=evidence.display_path(member),
        line_or_offset=lineno,
        raw=line,
        tags=tags,
        confidence=confidence,
        parser=PARSER_NAME,
        timestamp_quality=quality,
    )


def parse_line(line: str, lineno: int, member: str, evidence: Evidence, tracker: SyslogYearTracker) -> Event:
    if line[:1].isdigit():
        return _parse_iso_line(line, lineno, member, evidence)
    prefix = parse_syslog_prefix(line)
    if prefix is None:
        return _unparsed(evidence, member, lineno, line)
    try:
        timestamp_utc, quality, tz_tag = tracker.resolve(
            prefix["month"], prefix["day"], prefix["hour"], prefix["minute"], prefix["second"]
        )
    except ValueError:
        return _unparsed(evidence, member, lineno, line)
    return _build_event(
        evidence,
        member,
        lineno,
        line,
        prefix["proc"],
        prefix["pid"],
        prefix["message"],
        timestamp_utc,
        quality,
        tz_tag,
    )


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0, "repeated": 0})
    tracker = SyslogYearTracker(evidence.context.collection_time_utc, evidence.tzinfo, evidence.tz_source)
    pending: Event | None = None
    try:
        for lineno, line in evidence.iter_lines(member):
            stats["lines"] += 1
            if not line.strip():
                continue
            repeat = _match_repeat(line)
            if repeat is not None:
                if pending is not None:
                    pending.repeat_count += repeat
                    stats["repeated"] += repeat
                else:
                    orphan = _unparsed(evidence, member, lineno, line)
                    stats["events"] += 1
                    stats["unparsed"] += 1
                    yield orphan
                continue
            if pending is not None:
                stats["events"] += 1
                yield pending
            try:
                pending = parse_line(line, lineno, member, evidence, tracker)
            except Exception:
                pending = _unparsed(evidence, member, lineno, line)
            if pending.event_type == "unparsed":
                stats["unparsed"] += 1
        if pending is not None:
            stats["events"] += 1
            yield pending
    except Exception:
        if pending is not None:
            stats["events"] += 1
            yield pending
        raise
