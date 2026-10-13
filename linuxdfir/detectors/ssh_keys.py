"""Suspicious authorized_keys: root key sprawl, risky options, odd owners."""

from __future__ import annotations

from collections.abc import Iterable

from ..parsers.passwd_shadow_sudoers import parse_account_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "new_authorized_keys"

RULE_INFO = {
    RULE: {
        "why": (
            "Attackers persist with SSH keys: an extra root key, a forced command, or "
            "keys for service accounts that should never log in interactively."
        ),
        "next_steps": [
            "Remove unknown keys and re-verify the remaining ones with their owners.",
            "Check key file mtimes against the intrusion window.",
            "Review auth logs for logins using the rogue key.",
            "Consider forced-commands and from= restrictions for keys that must stay.",
        ],
    },
}

def _shell_allows_login(shell: str | None) -> bool:
    if not shell:
        return True
    base = shell.rsplit("/", 1)[-1]
    return base not in ("nologin", "false")


def detect(events: Iterable[Event]) -> list[Finding]:
    materialized = list(events)
    keys: list[Event] = [event for event in materialized if event.event_type == "ssh_key"]
    shells: dict[str, str | None] = {}
    for event in materialized:
        if event.event_type != "user_account":
            continue
        info = parse_account_message(event.message)
        if info is not None:
            shells[info["name"]] = info["shell"]
    findings: list[Finding] = []

    by_user: dict[str, list[Event]] = {}
    for event in keys:
        by_user.setdefault(event.user or "unknown", []).append(event)
    root_keys = by_user.get("root", [])
    if len(root_keys) >= 2:
        findings.append(
            Finding(
                id=make_finding_id(RULE, "root-multi", str(len(root_keys))),
                rule=RULE,
                severity=Severity.MEDIUM,
                title=f"Multiple authorized_keys for root ({len(root_keys)} keys)",
                description=" | ".join(event.message[:160] for event in root_keys),
                mitre_ids=["T1098.004"],
                count=len(root_keys),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in root_keys],
            )
        )

    for event in keys:
        if "key-options" not in event.tags:
            continue
        findings.append(
            Finding(
                id=make_finding_id(RULE, "options", event.evidence_path, str(event.line_or_offset)),
                rule=RULE,
                severity=Severity.MEDIUM,
                title=f"SSH key with options for {event.user or 'unknown'}",
                description=f"{event.message[:300]} — review forced commands and forwarding options.",
                mitre_ids=["T1098.004"],
                count=1,
                refs=[Ref(event.evidence_path, event.line_or_offset)],
            )
        )

    for user in sorted(by_user):
        shell = shells.get(user)
        if shell is not None and not _shell_allows_login(shell):
            user_keys = by_user[user]
            findings.append(
                Finding(
                    id=make_finding_id(RULE, "nologin", user),
                    rule=RULE,
                    severity=Severity.HIGH,
                    title=f"SSH keys for non-login account {user} (shell {shell})",
                    description=" | ".join(event.message[:160] for event in user_keys),
                    mitre_ids=["T1098.004"],
                    count=len(user_keys),
                    refs=[Ref(event.evidence_path, event.line_or_offset) for event in user_keys],
                )
            )
    return findings
