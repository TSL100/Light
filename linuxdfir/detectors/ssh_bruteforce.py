"""SSH brute force, password spraying and brute-force-then-success.

Pure functions over the normalized auth event stream. Failure bursts are
repeat-weighted: ``message repeated N times`` lines bump ``repeat_count``
on the previous event, and the true total (including repeats) drives both
thresholds and finding counts.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import timedelta

from ..parsers.auth_log import extract_ssh_failure, extract_ssh_success
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE_SUCCESS = "ssh_bruteforce_then_success"
RULE_BRUTEFORCE = "ssh_bruteforce"
RULE_SPRAY = "ssh_password_spraying"


def _weight(event: Event) -> int:
    return max(1, getattr(event, "repeat_count", 1))


def _loopback_note(ip: str) -> str:
    try:
        if ipaddress.ip_address(ip).is_loopback:
            return f" Source {ip} is loopback."
    except ValueError:
        pass
    return ""


def _sample_indices(total: int, keep: int) -> list[int]:
    if total <= keep or keep < 2:
        return list(range(total))
    picked = {0, total - 1}
    for step in range(1, keep - 1):
        picked.add(round(step * (total - 1) / (keep - 1)))
    return sorted(picked)


def _failure_refs(failures: list, max_refs: int) -> list[Ref]:
    refs = []
    for index in _sample_indices(len(failures), max_refs):
        event = failures[index][1]
        refs.append(Ref(event.evidence_path, event.line_or_offset))
    return refs


def detect(
    events: Iterable[Event],
    *,
    fail_threshold: int = 10,
    fail_window: int = 600,
    success_window: int = 1800,
    spray_threshold: int = 5,
    spray_high_threshold: int = 10,
    max_refs: int = 6,
    sudo_users: set[str] | None = None,
) -> list[Finding]:
    """Group ssh_failed_login events by source IP and emit findings.

    Windows are seconds: fail_threshold failures within fail_window, success
    within success_window after the last failure (and not before the first).
    sudo_users names accounts whose compromise is CRITICAL; root is always
    included.
    """
    privileged = {"root"} | set(sudo_users or ())
    failures: dict[str, list] = {}
    successes: dict[str, list] = {}
    for event in events:
        if event.timestamp_utc is None or event.source_artifact != "auth_log":
            continue
        if event.event_type == "ssh_failed_login":
            info = extract_ssh_failure(event.message)
            if info:
                failures.setdefault(info["ip"], []).append((event.timestamp_utc, event, info))
        elif event.event_type == "ssh_accepted_login":
            info = extract_ssh_success(event.message)
            if info:
                successes.setdefault(info["ip"], []).append((event.timestamp_utc, event, info))

    findings: list[Finding] = []
    for ip in sorted(failures):
        bursts = sorted(failures[ip], key=lambda item: item[0])
        best = 0
        running = 0
        start = 0
        for stamp, event, _info in bursts:
            running += _weight(event)
            while (stamp - bursts[start][0]).total_seconds() > fail_window:
                running -= _weight(bursts[start][1])
                start += 1
            best = max(best, running)
        total = sum(_weight(event) for _, event, _ in bursts)
        users = sorted({info["user"] for _, _, info in bursts})
        first_seen = bursts[0][0]
        last_failure = bursts[-1][0]
        candidates = [
            (stamp, event, info)
            for stamp, event, info in successes.get(ip, [])
            if first_seen <= stamp <= last_failure + timedelta(seconds=success_window)
        ]
        loopback = _loopback_note(ip)
        if best >= fail_threshold:
            if candidates:
                stamp, event, info = min(candidates, key=lambda item: item[0])
                critical = info["user"] in privileged
                findings.append(
                    Finding(
                        id=make_finding_id(RULE_SUCCESS, ip, info["user"], first_seen.isoformat()),
                        rule=RULE_SUCCESS,
                        severity=Severity.CRITICAL if critical else Severity.HIGH,
                        title=f"SSH brute force then success from {ip}",
                        description=(
                            f"{total} failed SSH logins from {ip} across {len(users)} account(s), "
                            f"followed by an accepted {info['method']} login for "
                            f"'{info['user']}' at {stamp.isoformat()}."
                            + (f" '{info['user']}' is privileged." if critical else "")
                            + loopback
                        ),
                        mitre_ids=["T1110.001", "T1078"],
                        first_seen=first_seen,
                        last_seen=stamp,
                        count=total,
                        refs=_failure_refs(bursts, max_refs - 1) + [Ref(event.evidence_path, event.line_or_offset)],
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=make_finding_id(RULE_BRUTEFORCE, ip, first_seen.isoformat()),
                        rule=RULE_BRUTEFORCE,
                        severity=Severity.MEDIUM,
                        title=f"SSH brute force from {ip} without observed success",
                        description=(
                            f"{total} failed SSH logins from {ip} across {len(users)} account(s) "
                            f"with no accepted login in the window.{loopback}"
                        ),
                        mitre_ids=["T1110.001"],
                        first_seen=first_seen,
                        last_seen=last_failure,
                        count=total,
                        refs=_failure_refs(bursts, max_refs),
                    )
                )
        if len(users) >= spray_threshold:
            high = len(users) >= spray_high_threshold
            findings.append(
                Finding(
                    id=make_finding_id(RULE_SPRAY, ip, ",".join(users)),
                    rule=RULE_SPRAY,
                    severity=Severity.HIGH if high else Severity.MEDIUM,
                    title=f"SSH password spraying from {ip}",
                    description=(
                        f"{ip} failed authentication as {len(users)} distinct users "
                        f"({', '.join(users[:12])}{'...' if len(users) > 12 else ''}) "
                        f"across {total} attempts.{loopback}"
                    ),
                    mitre_ids=["T1110.003"],
                    first_seen=first_seen,
                    last_seen=last_failure,
                    count=total,
                    refs=_failure_refs(bursts, max_refs),
                )
            )
    return findings
