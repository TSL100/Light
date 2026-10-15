"""Weakened sshd configuration (root login, password auth, empty passwords)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "sshd_config_weakening"

RULE_INFO = {
    RULE: {
        "why": (
            "Permitting root logins or password authentication widens the set of "
            "valid accounts that can be guessed or reused, and empty passwords "
            "remove the last barrier entirely."
        ),
        "next_steps": [
            "Set PermitRootLogin prohibit-password and PasswordAuthentication no where possible.",
            "Enforce key-only authentication and MFA for remaining password logins.",
            "Review accepted logins for the affected accounts around the change.",
        ],
    },
}

SETTING_RE = re.compile(r"^sshd:\s*(\S+)\s+(.*?)\s*$")

CHECKS: list[tuple[str, set[str], Severity, str]] = [
    ("permitrootlogin", {"yes", "true"}, Severity.MEDIUM, "root login permitted (prefer prohibit-password)"),
    ("passwordauthentication", {"yes", "true"}, Severity.LOW, "password authentication enabled"),
    ("permitemptypasswords", {"yes", "true"}, Severity.MEDIUM, "empty passwords permitted"),
    (
        "challengeresponseauthentication",
        {"yes", "true"},
        Severity.LOW,
        "challenge-response authentication enabled",
    ),
    ("kbdinteractiveauthentication", {"yes", "true"}, Severity.LOW, "keyboard-interactive authentication enabled"),
    ("pubkeyauthentication", {"no", "false"}, Severity.LOW, "public-key authentication disabled"),
    ("permituserenvironment", {"yes", "true"}, Severity.LOW, "user environment processing enabled"),
]

def detect(events: Iterable[Event]) -> list[Finding]:
    findings = []
    for event in events:
        if event.event_type != "sshd_setting":
            continue
        match = SETTING_RE.match(event.message)
        if not match:
            continue
        key, value = match.group(1).lower(), match.group(2).lower()
        for watched, bad_values, severity, note in CHECKS:
            if key == watched and value in bad_values:
                findings.append(
                    Finding(
                        id=make_finding_id(RULE, key, value, event.evidence_path, str(event.line_or_offset)),
                        rule=RULE,
                        severity=severity,
                        title=f"Weak sshd setting: {match.group(1)} {match.group(2)}",
                        description=f"{note} ({event.evidence_path}).",
                        mitre_ids=["T1078"],
                        count=1,
                        refs=[Ref(event.evidence_path, event.line_or_offset)],
                    )
                )
                break
    return findings
