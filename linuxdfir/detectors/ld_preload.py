"""LD_PRELOAD hijacking via ld.so.preload or environment injection."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "ld_preload_hijack"

RULE_INFO = {
    RULE: {
        "why": (
            "A preloaded library is injected into nearly every process on the host: "
            "the standard rootkit technique for hiding files, processes and network "
            "connections from defenders and monitoring tools."
        ),
        "next_steps": [
            "Clear /etc/ld.so.preload and any LD_PRELOAD exports, then reboot.",
            "Extract the library and analyze it (strings, sandbox detonation).",
            "Assume monitoring output from the host is untrustworthy; re-collect after cleanup.",
            "Hunt for the dropper that wrote the library (package logs, shell history).",
        ],
    },
}

LD_PRELOAD_ENV_RE = re.compile(r"\bLD_PRELOAD\s*=")


def detect(events: Iterable[Event]) -> list[Finding]:
    materialized = list(events)
    findings: list[Finding] = []

    by_file: dict[str, list[Event]] = {}
    for event in materialized:
        if event.event_type == "preload_entry":
            by_file.setdefault(event.evidence_path, []).append(event)
    for path in sorted(by_file):
        entries = by_file[path]
        libs = [event.message.rsplit(":", 1)[-1].strip() for event in entries]
        findings.append(
            Finding(
                id=make_finding_id(RULE, "preload-file", path),
                rule=RULE,
                severity=Severity.HIGH,
                title=f"LD_PRELOAD hijack: {path} preloads {len(entries)} librar{'y' if len(entries) == 1 else 'ies'}",
                description="Global library preload configured: " + ", ".join(libs),
                mitre_ids=["T1574.006"],
                count=len(entries),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in entries],
            )
        )

    by_env_file: dict[str, list[Event]] = {}
    for event in materialized:
        if event.event_type in ("systemd_env", "startup_line") and LD_PRELOAD_ENV_RE.search(event.message):
            by_env_file.setdefault(event.evidence_path, []).append(event)
    for path in sorted(by_env_file):
        entries = by_env_file[path]
        findings.append(
            Finding(
                id=make_finding_id(RULE, "preload-env", path),
                rule=RULE,
                severity=Severity.HIGH,
                title=f"LD_PRELOAD injected via environment in {path}",
                description=" | ".join(event.message.strip()[:200] for event in entries),
                mitre_ids=["T1574.006"],
                count=len(entries),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in entries],
            )
        )
    return findings
