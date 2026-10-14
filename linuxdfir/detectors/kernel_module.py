"""Unexpected kernel module loads (rootkit hint)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..parsers.syslog_kern import parse_kernel_module_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "kernel_module_load"

RULE_INFO = {
    RULE: {
        "why": (
            "Out-of-tree, unsigned or tainted kernel modules loaded outside "
            "installation activity are how rootkits hook the kernel to hide "
            "processes, files and connections."
        ),
        "next_steps": [
            "Identify the module file and extract it for analysis.",
            "Compare loaded modules (lsmod) against a known-good baseline.",
            "Check for hidden processes with an independent (e.g. memory) view.",
            "Rebuild or reimage if a malicious module is confirmed; patches will not evict it.",
        ],
    },
}

SUSPICIOUS_DETAIL_RE = re.compile(r"out-of-tree|taint|unsigned|staging|/tmp|/dev/shm|/var/tmp", re.IGNORECASE)


def detect(events: Iterable[Event]) -> list[Finding]:
    grouped: dict[str, list] = {}
    for event in events:
        if event.event_type != "kernel_module":
            continue
        info = parse_kernel_module_message(event.message)
        if info is None:
            continue
        if not SUSPICIOUS_DETAIL_RE.search(info["detail"]):
            continue
        grouped.setdefault(info["name"], []).append(event)
    findings = []
    for name in sorted(grouped):
        evts = grouped[name]
        findings.append(
            Finding(
                id=make_finding_id(RULE, name),
                rule=RULE,
                severity=Severity.MEDIUM,
                title=f"Suspicious kernel module load: {name}",
                description=" | ".join(event.message[:220] for event in evts[:3]),
                mitre_ids=["T1547.006"],
                count=len(evts),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in evts],
            )
        )
    return findings
