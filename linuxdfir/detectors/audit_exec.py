"""Suspicious commands observed by auditd EXECVE records."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..parsers.auditd import parse_audit_exec_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "audit_suspicious_exec"

RULE_INFO = {
    RULE: {
        "why": (
            "Kernel-level EXECVE records cannot be silenced by wiping shell "
            "history: downloaders, reverse shells and credential-file access "
            "seen here are high-confidence intrusion evidence."
        ),
        "next_steps": [
            "Correlate the EXECVE timestamp with network connections and file writes.",
            "Recover staged payloads and detonate them in a sandbox.",
            "Check for persistence installed in the same window.",
            "If /etc/shadow was touched, assume credential theft and rotate secrets.",
        ],
    },
}

EVIL_BIN_RE = re.compile(r"(?:^|/)(nc|ncat|socat|nmap|hydra|john|masscan|tcpdump)\b")
PIPE_SHELL_RE = re.compile(r"(curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b")
DOWNLOAD_TMP_RE = re.compile(r"(curl|wget)\b[^\n]*-(?:o|O)\s*\S*(?:/tmp|/dev/shm|/var/tmp)")
CHMOD_TMP_RE = re.compile(r"chmod\s+(?:\+x|[0-7]{3,4})\s+\S*(?:/tmp|/dev/shm|/var/tmp)")
BASE64_RE = re.compile(r"\bbase64\s+(?:-d|--decode)\b")
BASE64_SINK_RE = re.compile(r"\|\s*(?:ba)?sh\b|/tmp|/dev/shm|/var/tmp")
DEV_TCP_RE = re.compile(r"/dev/(?:tcp|udp)/")
SHADOW_RE = re.compile(r"/etc/(?:shadow|gshadow)\b")
AUID_UID_RE = re.compile(r"\bauid=(\d+)\s+uid=(\d+)\b")

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("evil-binary", EVIL_BIN_RE),
    ("pipe-to-shell", PIPE_SHELL_RE),
    ("download-to-tmp", DOWNLOAD_TMP_RE),
    ("chmod-tmp", CHMOD_TMP_RE),
    ("dev-tcp", DEV_TCP_RE),
    ("shadow-access", SHADOW_RE),
]


def _match_argv(argv: str) -> list[str]:
    hits = [key for key, pattern in PATTERNS if pattern.search(argv)]
    if BASE64_RE.search(argv) and BASE64_SINK_RE.search(argv):
        hits.append("base64-decode")
    return hits


def detect(events: Iterable[Event]) -> list[Finding]:
    materialized = list(events)
    findings: list[Finding] = []
    for event in materialized:
        if event.event_type != "audit_exec":
            continue
        info = parse_audit_exec_message(event.message)
        if info is None:
            continue
        hits = _match_argv(info["argv"])
        if not hits:
            continue
        mitre = ["T1003.008"] if "shadow-access" in hits else ["T1059"]
        findings.append(
            Finding(
                id=make_finding_id(RULE, ",".join(sorted(hits)), event.evidence_path, str(event.line_or_offset)),
                rule=RULE,
                severity=Severity.HIGH,
                title=f"Suspicious audited execution ({', '.join(sorted(hits))})",
                description=f"{event.message[:400]}",
                mitre_ids=mitre,
                count=1,
                refs=[Ref(event.evidence_path, event.line_or_offset)],
            )
        )
    for event in materialized:
        if event.event_type != "audit_event":
            continue
        match = AUID_UID_RE.search(event.message)
        if match is None:
            continue
        auid, uid = match.groups()
        if auid in ("0", "4294967295") or uid != "0":
            continue
        findings.append(
            Finding(
                id=make_finding_id(RULE, "priv-transition", auid, event.evidence_path, str(event.line_or_offset)),
                rule=RULE,
                severity=Severity.MEDIUM,
                title=f"Unprivileged audit session acting as root (auid={auid})",
                description=f"{event.message[:400]}",
                mitre_ids=["T1059"],
                count=1,
                refs=[Ref(event.evidence_path, event.line_or_offset)],
            )
        )
    return findings
