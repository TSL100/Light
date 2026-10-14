"""Suspicious live processes and listeners from ps/ss snapshots.

Signals (config-tunable via detection.toml [processes]): binaries running
from world-writable scratch paths or with ``(deleted)`` executables
(HIGH), reverse-shell command lines and cryptominer patterns (HIGH),
kernel-style masqueraded names that resolve to real paths (MEDIUM), and
LISTEN sockets on ports outside the allowed set (MEDIUM). Parent/child
structure comes from the ``depth:N`` ps auxf tag.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..config import load_config
from ..parsers.live_state import parse_process_message, parse_ss_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "suspicious_processes"

USES_CONFIG = True

RULE_INFO = {
    RULE: {
        "why": (
            "Live process and socket snapshots catch malware while it is running: "
            "scratch-path binaries, reverse shells, miners and unexpected listeners "
            "are the payload, not just persistence."
        ),
        "next_steps": [
            "Map the suspicious PID to its parent chain and originating file on disk.",
            "Check the listening port for outbound connections in ss/lsof and firewall logs.",
            "Remove the binary and kill the process; hunt for the same hash or path elsewhere.",
            "Review cron, systemd and shell history for the re-spawn mechanism.",
        ],
    },
}

SCRATCH_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
BRACKET_RE = re.compile(r"^\[[^\]]+\]$")


def _token0(command: str) -> str:
    return command.strip().split()[0] if command.strip() else ""


def _parent_stack(processes: list[tuple[Event, dict, int]]) -> dict[int, dict | None]:
    stack: dict[int, dict | None] = {}
    parents: dict[int, dict | None] = {}
    for event, info, depth in processes:
        while stack and max(stack) >= depth:
            stack.pop(max(stack))
        parents[id(event)] = stack.get(max(stack) - 1) if stack else None
        stack[depth] = info
    return parents


def _process_findings(
    events: Iterable[Event], cfg: dict, scratch_paths: tuple[str, ...]
) -> list[Finding]:
    miners = [p.lower() for p in cfg.get("miner_patterns", [])]
    shells = [p.lower() for p in cfg.get("reverse_shell_patterns", [])]
    processes: list[tuple[Event, dict, int]] = []
    for event in events:
        if event.event_type != "process":
            continue
        info = parse_process_message(event.message)
        if info is None:
            continue
        depth = 0
        for tag in event.tags:
            if tag.startswith("depth:"):
                try:
                    depth = int(tag.split(":", 1)[1])
                except ValueError:
                    depth = 0
        processes.append((event, info, depth))
    parents = _parent_stack(processes)
    findings: list[Finding] = []
    for event, info, _depth in processes:
        command = info["command"]
        lowered = command.lower()
        token0 = _token0(command)
        severity = None
        mitre = "T1105"
        reason = ""
        if "(deleted)" in command:
            severity = Severity.HIGH
            mitre = "T1055"
            reason = "running process from a deleted executable (in-memory malware)"
        elif token0.startswith(scratch_paths):
            severity = Severity.HIGH
            mitre = "T1105"
            reason = f"binary executing from a world-writable path ({token0})"
        elif any(pattern in lowered for pattern in shells):
            severity = Severity.HIGH
            mitre = "T1059.004"
            reason = "reverse-shell command line"
        elif any(pattern in lowered for pattern in miners):
            severity = Severity.HIGH
            mitre = "T1496"
            reason = "cryptominer command pattern"
        elif BRACKET_RE.match(token0) and "/" in command:
            severity = Severity.MEDIUM
            mitre = "T1036"
            reason = "kernel-style bracketed name with a real path in the command"
        if severity is None:
            continue
        parent = parents.get(id(event))
        parent_text = ""
        if parent is not None:
            parent_text = f" Parent: pid={parent['pid']} ({parent['command']})."
        findings.append(
            Finding(
                id=make_finding_id(RULE, str(info["pid"]), reason),
                rule=RULE,
                severity=severity,
                title=f"Suspicious process pid={info['pid']} ({reason})",
                description=(
                    f"User {info['user']} ran pid={info['pid']}: {command}. "
                    f"Reason: {reason}.{parent_text}"
                ),
                mitre_ids=[mitre],
                first_seen=event.timestamp_utc,
                count=1,
                refs=[Ref(event.evidence_path, event.line_or_offset)],
            )
        )
    return findings


def _listener_findings(events: Iterable[Event], allowed_ports: set[int]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if event.event_type != "ss_socket":
            continue
        fields = parse_ss_message(event.message)
        if fields is None or fields.get("state", "").upper() != "LISTEN":
            continue
        local = fields.get("local", "")
        port_text = local.rsplit(":", 1)[-1]
        if not port_text.isdigit():
            continue
        port = int(port_text)
        if port in allowed_ports:
            continue
        process = fields.get("process", "-")
        findings.append(
            Finding(
                id=make_finding_id(RULE, local, "unexpected-listener"),
                rule=RULE,
                severity=Severity.MEDIUM,
                title=f"Unexpected listener on port {port} ({local})",
                description=(
                    f"A process ({process}) is listening on {local}, which is outside "
                    "the configured allowed-port set. Unexpected listeners often mean "
                    "a backdoor or C2 callback channel."
                ),
                mitre_ids=["T1059.004"],
                first_seen=event.timestamp_utc,
                count=1,
                refs=[Ref(event.evidence_path, event.line_or_offset)],
            )
        )
    return findings


def detect(events: Iterable[Event], config: dict | None = None) -> list[Finding]:
    cfg = config if config is not None else load_config()
    process_cfg = cfg.get("processes", {})
    scratch_paths = tuple(cfg.get("scratch_exec", {}).get("paths", list(SCRATCH_PREFIXES)))
    allowed = {int(port) for port in process_cfg.get("allowed_ports", [22, 80, 443, 53])}
    events = list(events)
    findings = _process_findings(events, process_cfg, scratch_paths)
    findings.extend(_listener_findings(events, allowed))
    return findings
