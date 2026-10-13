"""Masked security services (defense impairment via systemctl mask)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath

from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "masked_security_service"

RULE_INFO = {
    RULE: {
        "why": (
            "Masking a security service (symlinking its unit to /dev/null) blinds "
            "auditing, logging or endpoint protection without stopping the system: "
            "a quiet way to neutralize defenses before or during an intrusion."
        ),
        "next_steps": [
            "Unmask and restart the service; verify it actually runs and logs.",
            "Find out who masked it (shell history, auditd, unit file mtime).",
            "Check for gaps in logs covering the masked period.",
            "Hunt for companion tampering (log deletion, other masked units).",
        ],
    },
}

SECURITY_UNITS = {
    "auditd",
    "audisp",
    "rsyslog",
    "syslog",
    "syslog-ng",
    "apparmor",
    "ufw",
    "firewalld",
    "falco",
    "osquery",
    "wazuh",
    "tripwire",
    "aide",
    "clamav",
}

BENIGN_UNITS = {"cups", "bluetooth"}

UNIT_SUFFIXES = (".service", ".timer", ".socket", ".target", ".path")


def _unit_base(original_path: str) -> str:
    name = PurePosixPath(original_path).name.lower()
    for suffix in UNIT_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def detect(events: Iterable[Event]) -> list[Finding]:
    findings = []
    for event in events:
        if event.event_type != "systemd_masked":
            continue
        base = _unit_base(event.evidence_path)
        ref = [Ref(event.evidence_path, event.line_or_offset)]
        if base in SECURITY_UNITS:
            findings.append(
                Finding(
                    id=make_finding_id(RULE, "security", base),
                    rule=RULE,
                    severity=Severity.HIGH,
                    title=f"Security service masked: {base}",
                    description=(
                        f"Systemd unit {event.evidence_path} is masked (symlinked to /dev/null), "
                        f"disabling {base}."
                    ),
                    mitre_ids=["T1562.001", "T1562.006"],
                    count=1,
                    refs=ref,
                )
            )
        elif base in BENIGN_UNITS:
            findings.append(
                Finding(
                    id=make_finding_id(RULE, "benign", base),
                    rule=RULE,
                    severity=Severity.INFO,
                    title=f"Benign unit masked: {base}",
                    description=f"Systemd unit {event.evidence_path} is masked; no security impact expected.",
                    mitre_ids=[],
                    count=1,
                    refs=ref,
                )
            )
        else:
            findings.append(
                Finding(
                    id=make_finding_id(RULE, "unknown", base),
                    rule=RULE,
                    severity=Severity.LOW,
                    title=f"Unclassified masked unit: {base}",
                    description=(
                        f"Systemd unit {event.evidence_path} is masked. Not a known security "
                        "service; review whether the mask is administrative."
                    ),
                    mitre_ids=[],
                    count=1,
                    refs=ref,
                )
            )
    return findings
