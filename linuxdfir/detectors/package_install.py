"""Attacker-tool package installs (nmap, netcat, password crackers...)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..parsers.package_logs import parse_package_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "suspicious_package_install"

RULE_INFO = {
    RULE: {
        "why": (
            "Scanners, netcat-style implants and password crackers installed via "
            "the package manager are the attacker's own tooling landing on the host."
        ),
        "next_steps": [
            "Determine who installed the tool (shell history, auth logs, apt history Commandline).",
            "Check whether the tool was executed and what it touched (firewall, listeners, captures).",
            "Remove the tool if it has no administrative justification.",
            "Hunt for companion tooling installed in the same window.",
        ],
    },
}

TOOLS = ("nmap", "netcat", "hydra", "john", "masscan", "tcpdump", "socat")
TOOL_RES = [re.compile(rf"(?:^|[-_.]){re.escape(tool)}(?:$|[-_.+]|\d)") for tool in TOOLS]


def _tool_name(name: str) -> str | None:
    lowered = name.lower()
    for tool, pattern in zip(TOOLS, TOOL_RES, strict=True):
        if pattern.search(lowered):
            return tool
    return None


def detect(events: Iterable[Event]) -> list[Finding]:
    grouped: dict[str, dict] = {}
    for event in events:
        if event.event_type not in ("package_install", "package_update"):
            continue
        info = parse_package_message(event.message)
        if info is None:
            continue
        tool = _tool_name(info["name"])
        if tool is None:
            continue
        group = grouped.setdefault(tool, {"events": [], "names": []})
        group["events"].append(event)
        if info["name"] not in group["names"]:
            group["names"].append(info["name"])
    findings = []
    for tool in sorted(grouped):
        group = grouped[tool]
        findings.append(
            Finding(
                id=make_finding_id(RULE, tool, ",".join(sorted(group["names"]))),
                rule=RULE,
                severity=Severity.MEDIUM,
                title=f"Attacker tool installed: {', '.join(sorted(group['names']))}",
                description=(
                    f"{len(group['events'])} install/update record(s) for {tool}-family tooling: "
                    + " | ".join(event.message[:160] for event in group["events"][:4])
                ),
                mitre_ids=["T1588.002"],
                count=len(group["events"]),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in group["events"]],
            )
        )
    return findings
