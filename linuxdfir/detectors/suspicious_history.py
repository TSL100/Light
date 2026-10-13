"""Suspicious shell-history commands (downloaders, shells, wipers)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "suspicious_history_commands"

RULE_INFO = {
    RULE: {
        "why": (
            "Downloaders piped into shells, reverse shells and history wiping in shell "
            "history are the classic traces of hands-on-keyboard intrusion and staging."
        ),
        "next_steps": [
            "Treat the owning account as compromised until proven otherwise; rotate its credentials.",
            "Retrieve the staged payloads (URLs, /tmp files) and detonate them in a sandbox.",
            "Hunt the same commands and source IPs across the fleet.",
            "Check for persistence (cron, systemd, authorized_keys) installed in the same window.",
        ],
    },
}

PATTERNS: list[tuple[str, re.Pattern, Severity, list[str]]] = [
    ("pipe_to_shell", re.compile(r"(curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b"), Severity.HIGH, ["T1059", "T1105"]),
    (
        "download_to_tmp",
        re.compile(r"(curl|wget)\b[^\n]*-(?:o|O)\s*\S*(?:/tmp|/dev/shm|/var/tmp)"),
        Severity.HIGH,
        ["T1105"],
    ),
    (
        "chmod_tmp",
        re.compile(r"chmod\s+(?:\+x|[0-7]{3,4})\s+\S*(?:/tmp|/dev/shm|/var/tmp)"),
        Severity.HIGH,
        ["T1059"],
    ),
    ("netcat_e", re.compile(r"\bnc(?:at)?\b[^\n]*-[a-zA-Z]*e\b"), Severity.HIGH, ["T1059"]),
    ("dev_tcp", re.compile(r"/dev/(?:tcp|udp)/"), Severity.HIGH, ["T1059"]),
    ("python_socket", re.compile(r"\bpython[23]?(?:\.\d+)?\s+-[cm]\s+[^\n]*socket"), Severity.HIGH, ["T1059"]),
    ("histfile_evasion", re.compile(r"HISTFILE\s*=\s*/dev/null|unset\s+HISTFILE"), Severity.MEDIUM, ["T1070.003"]),
    ("history_wipe", re.compile(r"\bhistory\s+-c\b"), Severity.MEDIUM, ["T1070.003"]),
    (
        "log_deletion",
        re.compile(r"\brm\b[^\n]*(?:/var/log/\S*|/var/log\b|wtmp|btmp|lastlog|auth\.log|syslog)"),
        Severity.MEDIUM,
        ["T1070.002"],
    ),
    ("crontab_r", re.compile(r"\bcrontab\s+-r\b"), Severity.MEDIUM, ["T1059"]),
    ("chattr", re.compile(r"\bchattr\b"), Severity.MEDIUM, ["T1059"]),
    ("ssh_keygen_authkeys", re.compile(r"\bssh-keygen\b|authorized_keys"), Severity.HIGH, ["T1059"]),
    ("useradd_history", re.compile(r"\b(?:useradd|adduser)\b"), Severity.HIGH, ["T1059"]),
]

BASE64_RE = re.compile(r"\bbase64\s+(?:-d|--decode)\b")
BASE64_SINK_RE = re.compile(r"\|\s*(?:ba)?sh\b|/tmp|/dev/shm|/var/tmp")

SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def _match_command(command: str) -> list[tuple[str, Severity, list[str]]]:
    hits = []
    for key, pattern, severity, mitre in PATTERNS:
        if pattern.search(command):
            hits.append((key, severity, mitre))
    if BASE64_RE.search(command) and BASE64_SINK_RE.search(command):
        hits.append(("base64_decode", Severity.HIGH, ["T1059"]))
    return hits


def detect(events: Iterable[Event]) -> list[Finding]:
    grouped: dict[tuple, dict] = {}
    for event in events:
        if event.event_type != "shell_command":
            continue
        hits = _match_command(event.message)
        if not hits:
            continue
        key = (event.user, event.evidence_path)
        group = grouped.setdefault(key, {"events": [], "hits": []})
        group["events"].append(event)
        group["hits"].extend((event, key, severity, mitre) for key, severity, mitre in hits)
    findings = []
    for (user, path), group in sorted(grouped.items(), key=lambda item: str(item[0])):
        severities = [severity for _, _, severity, _ in group["hits"]]
        top = max(severities, key=lambda s: SEVERITY_RANK[s])
        mitre: list[str] = []
        for _, _, _, ids in group["hits"]:
            for mid in ids:
                if mid not in mitre:
                    mitre.append(mid)
        details = []
        refs = []
        for event, key, _severity, _mitre in group["hits"]:
            details.append(f"L{event.line_or_offset} [{key}]: {event.message[:200]}")
            refs.append(Ref(event.evidence_path, event.line_or_offset))
        findings.append(
            Finding(
                id=make_finding_id(RULE, str(user), path),
                rule=RULE,
                severity=top,
                title=f"Suspicious shell history for {user or 'unknown'} in {path}",
                description=f"{len(group['hits'])} suspicious command(s): " + " | ".join(details),
                mitre_ids=mitre,
                first_seen=None,
                last_seen=None,
                count=len(group["hits"]),
                refs=refs,
            )
        )
    return findings
