"""New privileged accounts and sudoers changes."""

from __future__ import annotations

from collections.abc import Iterable

from ..parsers.passwd_shadow_sudoers import parse_account_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "new_user_or_sudoers_change"

RULE_INFO = {
    RULE: {
        "why": (
            "A second UID 0 account or a passwordless sudo grant hands attackers durable "
            "root access that survives password rotations."
        ),
        "next_steps": [
            "Disable or delete the rogue account and remove the sudo grant immediately.",
            "Determine how it was created (auth logs, shell history, auditd around the file mtime).",
            "Rotate credentials for every account that shared the host.",
            "Diff /etc/passwd and /etc/sudoers.d against a known-good baseline or backup.",
        ],
    },
}


def detect(events: Iterable[Event]) -> list[Finding]:
    materialized = list(events)
    accounts: list[tuple[Event, dict]] = []
    for event in materialized:
        if event.event_type != "user_account":
            continue
        info = parse_account_message(event.message)
        if info is not None:
            accounts.append((event, info))
    sudo_rules = [event for event in materialized if event.event_type == "sudo_rule"]
    findings: list[Finding] = []

    uid0 = [(event, info) for event, info in accounts if info["uid"] == 0]
    if len(uid0) > 1:
        names = sorted(info["name"] for _, info in uid0)
        interactive = sorted(
            info["name"] for _, info in accounts if info["interactive"] and info["name"] not in names
        )
        description = (
            f"{len(uid0)} accounts share UID 0 ({', '.join(names)}); only 'root' is expected. "
            f"Other interactive-shell accounts on this host: {', '.join(interactive) or 'none'}."
        )
        findings.append(
            Finding(
                id=make_finding_id(RULE, "uid0", ",".join(names)),
                rule=RULE,
                severity=Severity.HIGH,
                title=f"Multiple UID 0 accounts: {', '.join(names)}",
                description=description,
                mitre_ids=["T1136"],
                count=len(uid0),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event, _ in uid0],
            )
        )

    by_file: dict[str, list[Event]] = {}
    for event in sudo_rules:
        if "nopasswd" not in event.tags:
            continue
        by_file.setdefault(event.evidence_path, []).append(event)
    for path in sorted(by_file):
        rules = by_file[path]
        who = sorted({event.user or "?" for event in rules})
        findings.append(
            Finding(
                id=make_finding_id(RULE, "nopasswd", path),
                rule=RULE,
                severity=Severity.HIGH,
                title=f"Passwordless sudo in {path} ({', '.join(who)})",
                description=(
                    f"{len(rules)} NOPASSWD sudo grant(s) for {', '.join(who)}: "
                    + " | ".join(event.message[:160] for event in rules)
                ),
                mitre_ids=["T1548.003"],
                count=len(rules),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in rules],
            )
        )
    return findings
