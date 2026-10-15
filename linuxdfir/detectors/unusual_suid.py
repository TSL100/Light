"""Unusual SUID/SGID binaries from triage listings.

SUID/SGID files grant privilege escalation primitives; anything outside
the configured allowlist raises a finding. Binaries in world-writable
paths are HIGH regardless of name (any local user can drop /tmp/sudo with
mode 4755), everything else is MEDIUM and aggregated into one finding
per severity tier so a noisy host does not flood the report.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..config import load_config
from ..parsers.filesystem_suspicious import parse_fs_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "unusual_suid"

USES_CONFIG = True

RULE_INFO = {
    RULE: {
        "why": (
            "SUID/SGID bits turn any file into a privilege-escalation vector; "
            "world-writable paths let any local user place new ones, and "
            "package files can be trojanized."
        ),
        "next_steps": [
            "Verify the binary's signature or package provenance (dpkg -S, rpm -qf).",
            "Check whether the file is writable by non-root users or lives in a scratch path.",
            "Compare against a known-good baseline from a clean host of the same distro.",
            "Remove the SUID bit or the file once confirmed malicious.",
        ],
    },
}


def detect(events: Iterable[Event], config: dict | None = None) -> list[Finding]:
    cfg = config if config is not None else load_config()
    suid_cfg = cfg.get("suid", {})
    allowlist = {path.lower() for path in suid_cfg.get("allowlist", [])}
    writable = tuple(suid_cfg.get("writable_paths", []))
    highs: list[Event] = []
    mediums: list[Event] = []
    high_fields: dict[str, dict] = {}
    medium_fields: dict[str, dict] = {}
    for event in events:
        if event.event_type != "suid_sgid_file":
            continue
        fields = parse_fs_message(event.message)
        if fields is None:
            continue
        if fields.get("type") == "dir":
            continue
        path = fields.get("path", "")
        if not path or path.lower() in allowlist:
            continue
        if path.startswith(writable):
            highs.append(event)
            high_fields[path] = fields
        else:
            mediums.append(event)
            medium_fields[path] = fields
    findings: list[Finding] = []
    if highs:
        names = ", ".join(sorted(high_fields))
        findings.append(
            Finding(
                id=make_finding_id(RULE, "writable", names[:200]),
                rule=RULE,
                severity=Severity.HIGH,
                title=f"SUID/SGID binaries in writable paths ({len(highs)})",
                description=(
                    f"{len(highs)} SUID/SGID file(s) sit in world-writable locations: "
                    f"{names}. Writable-path SUID is the classic local privilege-escalation "
                    "drop (a mode 4755 binary any local user can replace); treat as hostile "
                    "until provenance is verified."
                ),
                mitre_ids=["T1548.001"],
                first_seen=highs[0].timestamp_utc,
                count=len(highs),
                refs=[Ref(ev.evidence_path, ev.line_or_offset) for ev in highs[:5]],
            )
        )
    if mediums:
        names = ", ".join(sorted(medium_fields))
        findings.append(
            Finding(
                id=make_finding_id(RULE, "unusual", names[:200]),
                rule=RULE,
                severity=Severity.MEDIUM,
                title=f"Unusual SUID/SGID binaries ({len(mediums)})",
                description=(
                    f"{len(mediums)} SUID/SGID file(s) are not in the configured "
                    f"allowlist: {names}. Custom SUID binaries are uncommon on a "
                    "hardened host; verify each against package provenance or a "
                    "clean baseline before trusting it."
                ),
                mitre_ids=["T1548.001"],
                first_seen=mediums[0].timestamp_utc,
                count=len(mediums),
                refs=[Ref(ev.evidence_path, ev.line_or_offset) for ev in mediums[:5]],
            )
        )
    return findings
