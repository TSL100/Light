"""Remote-access tooling: tunnels and mesh VPNs in units, cron or processes.

Matches cloudflared/ngrok/frp/chisel/ligolo, socat with tunnel-like
arguments, and tailscale/zerotier. These are dual-use: often legitimate
remote administration, occasionally attacker exfiltration/C2 channels,
so severities stay LOW (tunnels) and INFO (mesh VPNs) with that caveat
spelled out in every finding.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..parsers.cron import parse_cron_message
from ..parsers.live_processes import parse_process_message
from ..parsers.systemd_units import parse_exec_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "remote_access_tooling"

RULE_INFO = {
    RULE: {
        "why": (
            "Tunnel and mesh-VPN tools punch outbound channels that bypass "
            "perimeter controls. They are standard admin tooling too, so a "
            "finding here is a prompt to verify intent, not proof of intrusion."
        ),
        "next_steps": [
            "Ask the host owner whether the tool is sanctioned; check change records.",
            "Inspect where the tunnel points (config file, process args, DNS/flows).",
            "Correlate first-seen time with the intrusion window.",
            "Remove unsanctioned tools and rotate any credentials that crossed them.",
        ],
    },
}

CAVEAT = "These tools are often legitimate remote-administration aids; verify intent before escalating."

FAMILIES: list[tuple[str, re.Pattern[str], Severity, list[str]]] = [
    ("cloudflared", re.compile(r"\bcloudflared\b"), Severity.LOW, ["T1572", "T1090"]),
    ("ngrok", re.compile(r"\bngrok\b"), Severity.LOW, ["T1572", "T1090"]),
    ("frp", re.compile(r"(?:^|[/\s])frp[cs]?\b"), Severity.LOW, ["T1572", "T1090"]),
    ("chisel", re.compile(r"\bchisel\b"), Severity.LOW, ["T1572", "T1090"]),
    ("ligolo", re.compile(r"\bligolo(?:-ng)?\b"), Severity.LOW, ["T1572", "T1090"]),
    ("tailscale", re.compile(r"\btailscale[d]?\b"), Severity.INFO, ["T1572"]),
    ("zerotier", re.compile(r"\bzerotier(?:-one)?\b"), Severity.INFO, ["T1572"]),
]
SOCAT_RE = re.compile(r"\bsocat\b")
SOCAT_TUNNEL_RE = re.compile(r"\b(EXEC|SYSTEM|OPENSSL|TCP-LISTEN|UDP-LISTEN|PTY|TUN)\b|:TCP:|:UDP:", re.IGNORECASE)


def _commands(event: Event) -> list[tuple[str, str]]:
    """Return (source, command) pairs extractable from persistence/process events."""
    if event.event_type == "cron_job":
        info = parse_cron_message(event.message)
        if info is not None and info["command"].strip():
            schedule = info["schedule"]
            return [(f"cron [{schedule}]", info["command"])]
    elif event.event_type == "systemd_exec":
        info = parse_exec_message(event.message)
        if info is not None and info["value"].strip():
            return [(info["key"], info["value"])]
    elif event.event_type == "process":
        info = parse_process_message(event.message)
        if info is not None and info["command"].strip():
            return [("process", info["command"])]
    return []


def detect(events: Iterable[Event]) -> list[Finding]:
    grouped: dict[str, dict] = {}
    for event in events:
        for source, command in _commands(event):
            for family, pattern, severity, mitre in FAMILIES:
                if pattern.search(command):
                    group = grouped.setdefault(
                        family, {"severity": severity, "mitre": mitre, "hits": []}
                    )
                    group["hits"].append((event, source, command))
                    break
            else:
                if SOCAT_RE.search(command) and SOCAT_TUNNEL_RE.search(command):
                    group = grouped.setdefault(
                        "socat", {"severity": Severity.LOW, "mitre": ["T1572", "T1090"], "hits": []}
                    )
                    group["hits"].append((event, source, command))
    findings = []
    for family in sorted(grouped):
        group = grouped[family]
        hits = group["hits"]
        detail = " | ".join(f"{source}: {command[:160]}" for _, source, command in hits[:4])
        findings.append(
            Finding(
                id=make_finding_id(RULE, family),
                rule=RULE,
                severity=group["severity"],
                title=f"Remote-access tooling present: {family} ({len(hits)} occurrence(s))",
                description=f"{detail}. {CAVEAT}",
                mitre_ids=group["mitre"],
                count=len(hits),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event, _, _ in hits],
            )
        )
    return findings
