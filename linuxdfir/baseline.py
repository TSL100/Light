"""Clean-baseline drift comparison.

A baseline is a second event stream from a known-clean host (same distro,
same role, collected the same way). Each side is reduced to a profile of
six stable sets — users, SUID/SGID paths, cron entries, systemd units,
packages and listeners — and the target is diffed against the baseline.
Additions and removals become ``baseline_*`` findings.

Only categories with coverage on *both* sides are compared: if either side
produced no events for a category (e.g. the baseline was collected with
``--skip-live`` so it has no listeners), that category is counted as
``skipped_no_coverage`` instead of flooding the report with meaningless
additions or removals.

Identity keys are deliberately narrow (usernames, paths, schedule+user+
command, unit paths, package names, socket+process). Attribute changes
without add/remove (a unit file edited in place) are out of scope and
belong to the content detectors.

No optional dependencies: stdlib only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .config import load_config
from .parsers.cron import parse_cron_message
from .parsers.filesystem_suspicious import parse_fs_message
from .parsers.live_state import parse_ss_message
from .parsers.package_logs import parse_package_message
from .schema import Event, Finding, Ref, Severity, make_finding_id, parse_severity

RULES = (
    "baseline_users",
    "baseline_suid",
    "baseline_cron",
    "baseline_systemd",
    "baseline_packages",
    "baseline_listeners",
)

RULE_INFO = {
    "baseline_users": {
        "why": (
            "Accounts present on the host but absent from the clean baseline "
            "are the most direct persistence signal: backdoors add users, and "
            "missing accounts can mean tampering or an incompletely rebuilt host."
        ),
        "next_steps": [
            "Confirm each added account with the host owner; disable unknown ones.",
            "Check when the account was created (auth logs, shadow mtime) and how it authenticates.",
            "For removed accounts, verify the removal was an authorized change.",
        ],
    },
    "baseline_suid": {
        "why": (
            "A SUID/SGID binary that the clean baseline does not have is a "
            "privilege-escalation primitive waiting for a local user; a "
            "vanished one may mean a package was replaced or trojanized."
        ),
        "next_steps": [
            "Verify the binary's package provenance (dpkg -S, rpm -qf).",
            "Check whether it lives in a writable path or is world-writable.",
            "Diff the binary hash against the distro package.",
        ],
    },
    "baseline_cron": {
        "why": (
            "Cron entries absent from the clean baseline are scheduled "
            "persistence until proven to be admin work; removed entries can "
            "mean disabled monitoring or log rotation."
        ),
        "next_steps": [
            "Read the added entry's command and recover the payload it runs.",
            "Correlate the entry's file mtime with logins and package installs.",
            "Confirm removed entries were an authorized cleanup.",
        ],
    },
    "baseline_systemd": {
        "why": (
            "Unit files absent from the clean baseline are service-level "
            "persistence; removed units can mean blinded defenses (auditd, "
            "logging) or decommissioned software."
        ),
        "next_steps": [
            "Read the added unit's Exec lines and recover the payload.",
            "Check whether the unit is enabled and currently active.",
            "For removed units, verify against change records.",
        ],
    },
    "baseline_packages": {
        "why": (
            "Packages installed on the host but not on the clean baseline "
            "are dual-use tooling candidates; removals can break monitoring "
            "or indicate image drift."
        ),
        "next_steps": [
            "Determine who installed the package (apt history Commandline, shell history).",
            "Check whether the tool was executed and what it touched.",
            "Confirm the baseline image matches the host's distro and role first.",
        ],
    },
    "baseline_listeners": {
        "why": (
            "A listening socket the clean baseline never had is an open door: "
            "backdoor listener, tunnel endpoint or admin service nobody "
            "recorded. Vanished listeners can mean a killed implant — or a "
            "dead service."
        ),
        "next_steps": [
            "Map the listener to its process and binary; hash the binary.",
            "Check firewall rules and what the port talks to.",
            "Re-collect live state to confirm it is still listening.",
        ],
    },
}

_MITRE = {
    "baseline_users": ["T1136"],
    "baseline_suid": ["T1548.001"],
    "baseline_cron": ["T1053.003"],
    "baseline_systemd": ["T1543.002"],
    "baseline_packages": ["T1588.002"],
    "baseline_listeners": ["T1059.004"],
}

_LABELS = {
    "baseline_users": "user(s)",
    "baseline_suid": "SUID/SGID path(s)",
    "baseline_cron": "cron job(s)",
    "baseline_systemd": "systemd unit(s)",
    "baseline_packages": "package(s)",
    "baseline_listeners": "listener(s)",
}

_EVENT_TYPES = {
    "baseline_users": ("user_account",),
    "baseline_suid": ("suid_sgid_file",),
    "baseline_cron": ("cron_job",),
    "baseline_systemd": ("systemd_unit",),
    "baseline_packages": ("package_install", "package_update"),
    "baseline_listeners": ("ss_socket",),
}

_MAX_LISTED = 25
_MAX_REFS = 5

_ACCOUNT_RE = re.compile(r"^account (\S+):")


def _user_key(event: Event) -> str | None:
    if event.user:
        return event.user
    match = _ACCOUNT_RE.match(event.message or "")
    return match.group(1) if match else None


def _suid_key(event: Event) -> str | None:
    fields = parse_fs_message(event.message or "")
    if fields is None or fields.get("type") == "dir":
        return None
    path = fields.get("path", "")
    return path or None


def _cron_key(event: Event) -> str | None:
    info = parse_cron_message(event.message or "")
    if info is None:
        return None
    return "\x00".join((info.get("schedule", ""), info.get("user", ""), info.get("command", "")))


def _systemd_key(event: Event) -> str | None:
    return event.evidence_path or None


def _package_key(event: Event) -> str | None:
    info = parse_package_message(event.message or "")
    if info is None:
        return None
    return info["name"].lower() or None


def _listener_key(event: Event) -> str | None:
    fields = parse_ss_message(event.message or "")
    if fields is None or fields.get("state", "").upper() != "LISTEN":
        return None
    procname = (fields.get("process") or "-").split("/")[0] or "-"
    local = fields.get("local", "?")
    netid = fields.get("netid", "?")
    return f"{netid} {local} {procname}"


_KEY_FNS = {
    "baseline_users": _user_key,
    "baseline_suid": _suid_key,
    "baseline_cron": _cron_key,
    "baseline_systemd": _systemd_key,
    "baseline_packages": _package_key,
    "baseline_listeners": _listener_key,
}


def _default_added_severity(config: dict | None) -> Severity:
    raw = (config or {}).get("baseline", {}).get("severity_added", Severity.HIGH.value)
    try:
        return parse_severity(str(raw))
    except ValueError:
        return Severity.HIGH


def _default_removed_severity(config: dict | None) -> Severity:
    raw = (config or {}).get("baseline", {}).get("severity_removed", Severity.MEDIUM.value)
    try:
        return parse_severity(str(raw))
    except ValueError:
        return Severity.MEDIUM


def extract_profile(events: Iterable[Event]) -> dict[str, dict[str, Event]]:
    """Reduce an event stream to {category_rule: {identity_key: first_event}}."""
    profile: dict[str, dict[str, Event]] = {rule: {} for rule in RULES}
    for event in events:
        for rule in RULES:
            if event.event_type not in _EVENT_TYPES[rule]:
                continue
            try:
                key = _KEY_FNS[rule](event)
            except Exception:
                continue
            if key and key not in profile[rule]:
                profile[rule][key] = event
    return profile


def _summarize(keys: list[str]) -> str:
    shown = ", ".join(keys[:_MAX_LISTED])
    if len(keys) > _MAX_LISTED:
        shown += f" (+{len(keys) - _MAX_LISTED} more)"
    return shown


def diff_profiles(
    target_profile: dict[str, dict[str, Event]],
    baseline_profile: dict[str, dict[str, Event]],
    config: dict | None = None,
    *,
    target_label: str = "target",
    baseline_label: str = "baseline",
) -> tuple[list[Finding], dict]:
    """Diff two profiles; one finding per (category, direction) with drift."""
    added_severity = _default_added_severity(config)
    removed_severity = _default_removed_severity(config)
    findings: list[Finding] = []
    categories: dict = {}
    for rule in RULES:
        target_keys = target_profile.get(rule, {})
        baseline_keys = baseline_profile.get(rule, {})
        entry: dict = {
            "baseline_count": len(baseline_keys),
            "target_count": len(target_keys),
            "added": 0,
            "removed": 0,
            "compared": False,
        }
        if not target_keys or not baseline_keys:
            missing = []
            if not baseline_keys:
                missing.append("baseline")
            if not target_keys:
                missing.append("target")
            entry["skipped_no_coverage"] = missing
            categories[rule] = entry
            continue
        entry["compared"] = True
        added = sorted(set(target_keys) - set(baseline_keys))
        removed = sorted(set(baseline_keys) - set(target_keys))
        entry["added"] = len(added)
        entry["removed"] = len(removed)
        label = _LABELS[rule]
        if added:
            refs = [Ref(target_keys[k].evidence_path, target_keys[k].line_or_offset) for k in added[:_MAX_REFS]]
            findings.append(
                Finding(
                    id=make_finding_id(rule, "added", ",".join(added)),
                    rule=rule,
                    severity=added_severity,
                    title=f"Baseline drift: {len(added)} {label} added vs baseline ({_summarize(added)})",
                    description=(
                        f"{len(added)} {label} present on {target_label} but absent from "
                        f"{baseline_label}: {_summarize(added)}. Verify each item with the "
                        "host owner; treat unknown additions as hostile until proven otherwise."
                    ),
                    mitre_ids=list(_MITRE[rule]),
                    count=len(added),
                    refs=refs,
                )
            )
        if removed:
            refs = [Ref(baseline_keys[k].evidence_path, baseline_keys[k].line_or_offset) for k in removed[:_MAX_REFS]]
            findings.append(
                Finding(
                    id=make_finding_id(rule, "removed", ",".join(removed)),
                    rule=rule,
                    severity=removed_severity,
                    title=f"Baseline drift: {len(removed)} {label} removed vs baseline ({_summarize(removed)})",
                    description=(
                        f"{len(removed)} {label} present on {baseline_label} but absent from "
                        f"{target_label}: {_summarize(removed)}. Confirm the removal was an "
                        "authorized change; unexpected removals can mean disabled defenses."
                    ),
                    mitre_ids=list(_MITRE[rule]),
                    count=len(removed),
                    refs=refs,
                )
            )
        categories[rule] = entry
    stats: dict = {
        "status": "ok",
        "target": target_label,
        "baseline": baseline_label,
        "categories": categories,
        "compared": sum(1 for entry in categories.values() if entry["compared"]),
        "findings": len(findings),
    }
    return findings, stats


def scan_with_baseline(
    target_events: Iterable[Event],
    baseline_events: Iterable[Event],
    config: dict | None = None,
    *,
    target_label: str = "target",
    baseline_label: str = "baseline",
) -> tuple[list[Finding], dict]:
    """Profile both sides and diff; pure function over event streams."""
    cfg = config if config is not None else load_config()
    target_profile = extract_profile(target_events)
    baseline_profile = extract_profile(baseline_events)
    return diff_profiles(
        target_profile, baseline_profile, cfg,
        target_label=target_label, baseline_label=baseline_label,
    )
