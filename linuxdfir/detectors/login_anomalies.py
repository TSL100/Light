"""Login anomalies from binary login records (wtmp/btmp/lastlog).

Correlates successful wtmp logins with btmp failures from the same IP
(brute-force-then-login), flags btmp spikes and logins outside the
configured business-hours window (host timezone, carried in the parser
message), plus direct root logins not already explained by a
brute-force correlation.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..config import load_config
from ..parsers.wtmp_btmp_lastlog import parse_login_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "login_anomalies"

USES_CONFIG = True

RULE_INFO = {
    RULE: {
        "why": (
            "A successful login from an address that also stacks failed logins "
            "means the guessing worked; night-time and direct-root logins are "
            "the follow-on interactive access to scrutinize."
        ),
        "next_steps": [
            "Treat the source address as hostile; block it at the perimeter.",
            "Reset credentials for the logged-in account and inspect its authorized_keys.",
            "Review what the session did (shell history, auditd, new processes).",
            "Confirm the login hour is abnormal for this host's operators before escalating.",
        ],
    },
}


def _outside_business_hours(hour: int, start: int, end: int) -> bool:
    """True when `hour` falls outside the [start, end) business window."""
    if start == end:
        return False
    if start < end:
        return hour < start or hour >= end
    return start <= hour < end


def _time_span(events: list) -> tuple:
    stamps = [event.timestamp_utc for event in events if event.timestamp_utc is not None]
    if not stamps:
        return None, None
    return min(stamps), max(stamps)


def detect(
    events: Iterable[Event],
    *,
    config: dict | None = None,
    night_start: int | None = None,
    night_end: int | None = None,
    spike_threshold: int = 20,
    spike_window: int = 600,
) -> list[Finding]:
    cfg = config if config is not None else load_config()
    hours = cfg.get("business_hours", {}) or {}
    start = int(hours.get("start", 8))
    end = int(hours.get("end", 18))
    if night_start is not None:
        start = night_start
        end = night_end if night_end is not None else end
    logins: list[tuple[Event, dict]] = []
    failures: list[tuple[Event, dict]] = []
    lastlogs: list[tuple[Event, dict]] = []
    for event in events:
        info = None
        if event.event_type == "wtmp_login":
            info = parse_login_message(event.message)
            if info is not None:
                logins.append((event, info))
        elif event.event_type == "btmp_failure":
            info = parse_login_message(event.message)
            if info is not None:
                failures.append((event, info))
        elif event.event_type == "lastlog_entry":
            info = parse_login_message(event.message)
            if info is not None:
                lastlogs.append((event, info))
    findings: list[Finding] = []
    failure_ips = {info["ip"] for _, info in failures}
    correlated: set[int] = set()

    lastlog_by_ip: dict[str, list] = {}
    for event, info in lastlogs:
        if info.get("uid") == 0:
            lastlog_by_ip.setdefault(info["ip"], []).append(event)

    for event, info in logins:
        if info["ip"] in failure_ips:
            correlated.add(id(event))
            extra_events = [
                evt
                for evt in lastlog_by_ip.get(info["ip"], [])
                if info["user"] == "root"
            ]
            extra_refs = [
                Ref(evt.evidence_path, evt.line_or_offset) for evt in extra_events
            ]
            first_seen, last_seen = _time_span([event, *extra_events])
            findings.append(
                Finding(
                    id=make_finding_id(RULE, "bruteforced-ip", info["user"] or "?", info["ip"]),
                    rule=RULE,
                    severity=Severity.HIGH,
                    title=f"Login from brute-forced IP {info['ip']} as {info['user'] or '?'}",
                    description=(
                        f"Successful {info['kind']} for '{info['user'] or '?'}' from {info['ip']} "
                        f"({info['tty']}), an address with recorded failed logins."
                        + (" Root last-login corroborates." if extra_refs else "")
                    ),
                    mitre_ids=["T1078"],
                    first_seen=first_seen,
                    last_seen=last_seen,
                    count=1,
                    refs=[Ref(event.evidence_path, event.line_or_offset), *extra_refs],
                )
            )

    dated = sorted(
        [(event.timestamp_utc, event) for event, _ in failures if event.timestamp_utc is not None]
    )
    best = 0
    running: list = []
    for stamp, event in dated:
        running.append((stamp, event))
        while (stamp - running[0][0]).total_seconds() > spike_window:
            running.pop(0)
        best = max(best, len(running))
    if best >= spike_threshold and dated:
        findings.append(
            Finding(
                id=make_finding_id(RULE, "btmp-spike", str(best)),
                rule=RULE,
                severity=Severity.MEDIUM,
                title=f"Failed-login spike in btmp ({best} in {spike_window}s)",
                description=f"{best} failed logins within {spike_window} seconds across all sources.",
                mitre_ids=["T1110.001"],
                first_seen=dated[0][0],
                last_seen=dated[-1][0],
                count=best,
                refs=[Ref(event.evidence_path, event.line_or_offset) for _, event in dated[:6]],
            )
        )

    night: dict[str, list] = {}
    for event, info in logins:
        hour = info.get("hour")
        if hour is None or not _outside_business_hours(hour, start, end):
            continue
        night.setdefault(info["user"] or "?", []).append(event)
    for user in sorted(night):
        evts = night[user]
        first_seen, last_seen = _time_span(evts)
        findings.append(
            Finding(
                id=make_finding_id(RULE, "night-login", user),
                rule=RULE,
                severity=Severity.LOW,
                title=(
                    f"Unusual-hour login(s) for {user} "
                    f"(outside business hours {start:02d}:00-{end:02d}:00 local)"
                ),
                description=(
                    f"{len(evts)} login(s) outside business hours "
                    f"{start:02d}:00-{end:02d}:00 (host-local time)."
                ),
                mitre_ids=["T1078"],
                first_seen=first_seen,
                last_seen=last_seen,
                count=len(evts),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in evts],
            )
        )

    for event, info in logins:
        if info["user"] != "root" or id(event) in correlated:
            continue
        findings.append(
            Finding(
                id=make_finding_id(RULE, "root-direct", info["ip"], str(info.get("hour"))),
                rule=RULE,
                severity=Severity.LOW,
                title=f"Direct root login from {info['ip']}",
                description=f"root logged in from {info['ip']} ({info['tty']}) with no btmp failures from it.",
                mitre_ids=["T1078"],
                first_seen=event.timestamp_utc,
                last_seen=event.timestamp_utc,
                count=1,
                refs=[Ref(event.evidence_path, event.line_or_offset)],
            )
        )
    for event, info in lastlogs:
        if info.get("uid") != 0 or info["ip"] in failure_ips:
            continue
        findings.append(
            Finding(
                id=make_finding_id(RULE, "root-lastlog", info["ip"]),
                rule=RULE,
                severity=Severity.LOW,
                title=f"Direct root last-login from {info['ip']}",
                description=f"uid 0 last recorded from {info['ip']} ({info['tty']}) with no btmp failures from it.",
                mitre_ids=["T1078"],
                first_seen=event.timestamp_utc,
                last_seen=event.timestamp_utc,
                count=1,
                refs=[Ref(event.evidence_path, event.line_or_offset)],
            )
        )
    return findings
