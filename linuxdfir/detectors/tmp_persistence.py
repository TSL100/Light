"""Persistence via world-writable or hidden paths (cron jobs, systemd exec)."""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable

from ..parsers.cron import parse_cron_message
from ..parsers.systemd_units import parse_exec_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "persistence_from_tmp_paths"

RULE_INFO = {
    RULE: {
        "why": (
            "Scheduled tasks and services executing from /tmp, /dev/shm, /var/tmp or "
            "hidden directories run from attacker-writable locations that rarely survive "
            "reboots or scrutiny: a textbook persistence implant."
        ),
        "next_steps": [
            "Kill the payload processes and remove the cron entry or unit file.",
            "Recover the payload binary/script from /tmp or /dev/shm before it vanishes.",
            "Determine the initial access vector that planted it (auth logs, web logs).",
            "Verify no sibling persistence exists (other cron files, timers, rc scripts).",
        ],
    },
}

TMP_MARKERS = ("/tmp/", "/dev/shm", "/var/tmp")
HIDDEN_PART_RE = re.compile(r"(?:^|/)\.[^/]+")


def _command_texts(command: str) -> list[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    return [command, *tokens]


def _suspicious_spans(command: str) -> list[str]:
    spans = []
    lowered = command
    for marker in TMP_MARKERS:
        if marker in lowered:
            spans.append(marker.rstrip("/"))
    for text in _command_texts(command):
        for match in HIDDEN_PART_RE.finditer(text):
            spans.append(match.group(0))
    deduped = []
    for span in spans:
        if span not in deduped:
            deduped.append(span)
    return deduped


def _cron_item(event: Event) -> tuple | None:
    info = parse_cron_message(event.message)
    if info is None or not info["command"].strip():
        return None
    spans = _suspicious_spans(info["command"])
    if not spans:
        return None
    return ("cron", info["user"], info["schedule"], info["command"], spans, ["T1053.003"])


def _systemd_item(event: Event) -> tuple | None:
    info = parse_exec_message(event.message)
    if info is None or not info["value"].strip():
        return None
    spans = _suspicious_spans(info["value"])
    if not spans:
        return None
    return ("systemd", info["user"], info["key"], info["value"], spans, ["T1543.002"])


def detect(events: Iterable[Event]) -> list[Finding]:
    grouped: dict[tuple, dict] = {}
    for event in events:
        item = None
        if event.event_type == "cron_job":
            item = _cron_item(event)
        elif event.event_type == "systemd_exec":
            item = _systemd_item(event)
        if item is None:
            continue
        kind, user, schedule, command, spans, mitre = item
        key = (kind, user, schedule, command)
        group = grouped.setdefault(key, {"events": [], "spans": [], "mitre": mitre, "schedule": schedule})
        group["events"].append(event)
        for span in spans:
            if span not in group["spans"]:
                group["spans"].append(span)
    findings = []
    for (kind, user, _schedule, command), group in sorted(grouped.items(), key=lambda item: str(item[0])):
        findings.append(
            Finding(
                id=make_finding_id(RULE, kind, str(user), command),
                rule=RULE,
                severity=Severity.HIGH,
                title=f"Persistence from suspicious path ({kind}): {command[:120]}",
                description=(
                    f"{kind} persistence for '{user}' executes '{command}' touching "
                    f"suspicious location(s): {', '.join(group['spans'])} "
                    f"(schedule: {group['schedule']})."
                ),
                mitre_ids=group["mitre"],
                count=len(group["events"]),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in group["events"]],
            )
        )
    return findings
