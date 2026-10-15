"""Transparent risk scoring: per-host and per-user, with breakdowns.

Two-stage bounded formula (no hard saturation):

1. Diminishing returns per rule — findings of the same rule are sorted by
   weight (descending, ties by finding id) and each subsequent finding
   contributes ``decay^i`` of its weight (``[scoring] decay``, default
   0.5). This caps any single noisy rule at ``max_weight / (1 - decay)``
   no matter how many findings it emits, so 40 LOW findings of one rule
   cannot out-weigh a handful of HIGH findings.

2. Smooth asymptote — the damped total is mapped to 0..cap with
   ``score = cap * (1 - exp(-total / cap))`` (``[scoring] cap``,
   default 100). The score is strictly increasing in the evidence but
   never reaches the cap, so a noisy "lots of LOW" host stays visibly
   below a host with HIGH/CRITICAL findings instead of both pinning at
   100.

``raw_score`` remains the plain sum of severity weights (pre-damping) so
callers can always see the unadjusted signal volume. Per-user scores
attribute each finding's weight to every username named in its
title/description, split evenly, then apply the same decay + asymptote.
Every contributing finding is listed in the breakdown with both its raw
and damped weight — the number is never a black box.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable

from .iocs import extract_users
from .schema import Event, Finding

DEFAULT_WEIGHTS = {
    "critical": 100,
    "high": 40,
    "medium": 10,
    "low": 2,
    "info": 0,
}
DEFAULT_CAP = 100
DEFAULT_DECAY = 0.5

METHOD = (
    "per-rule diminishing weights (each additional finding of the same rule "
    "counts decay^i of its severity weight, so one noisy rule is capped at "
    "max_weight/(1-decay)); host/user score = cap*(1-exp(-total/cap)), which "
    "is strictly increasing but never saturates at the cap; per-user score "
    "splits each finding's weight across usernames named in its "
    "title/description"
)


def _most_common_host(events: Iterable[Event]) -> str | None:
    counts: Counter[str] = Counter()
    for event in events:
        if event.host:
            counts[event.host] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def _decay_sorted(values: Iterable[float], decay: float) -> list[float]:
    """Return decayed values: largest full, each next multiplied by decay^i."""
    return [value * (decay**index) for index, value in enumerate(sorted(values, reverse=True))]


def _asymptote_score(total: float, cap: float) -> float:
    if total <= 0:
        return 0.0
    score = cap * (1.0 - math.exp(-total / cap))
    # Round for display, but never let rounding promote a sub-cap score to
    # the cap itself: the whole point of the asymptote is that it approaches
    # but never reaches the cap, so noisy evidence stays distinguishable.
    rounded = round(score, 2)
    if rounded >= cap and score < cap:
        rounded = round(cap - 0.01, 2)
    return rounded


def score_findings(
    findings: Iterable[Finding],
    events: Iterable[Event] | None = None,
    config: dict | None = None,
    host: str | None = None,
) -> dict:
    """Return ``{"hosts": {...}, "users": {...}, "weights": {...}, "method": ...}``."""
    scoring_cfg = (config or {}).get("scoring", {}) or {}
    weights = dict(DEFAULT_WEIGHTS)
    for name, value in (scoring_cfg.get("weights") or {}).items():
        weights[str(name)] = int(value)
    cap = float(scoring_cfg.get("cap", DEFAULT_CAP))
    decay = float(scoring_cfg.get("decay", DEFAULT_DECAY))
    if not 0.0 <= decay < 1.0:
        raise ValueError(f"scoring decay must be in [0, 1): {decay!r}")
    if cap <= 0:
        raise ValueError(f"scoring cap must be positive: {cap!r}")

    if host is None and events is not None:
        host = _most_common_host(events)
    host = host or "unknown"

    items = list(findings)
    by_severity: dict[str, int] = {}
    raw_total = 0
    for finding in items:
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
        raw_total += int(weights.get(finding.severity.value, 0))

    # Damped weight per finding: within each rule, largest weight first.
    damped_by_finding: dict[str, float] = {}
    by_rule: dict[str, list[Finding]] = {}
    for finding in items:
        by_rule.setdefault(finding.rule, []).append(finding)
    for rule_findings in by_rule.values():
        ordered = sorted(
            rule_findings,
            key=lambda f: (-int(weights.get(f.severity.value, 0)), f.id),
        )
        for index, finding in enumerate(ordered):
            weight = float(int(weights.get(finding.severity.value, 0)))
            damped_by_finding[finding.id] = weight * (decay**index)

    damped_total = sum(damped_by_finding.values())
    score = _asymptote_score(damped_total, cap)

    breakdown = [
        {
            "finding_id": finding.id,
            "rule": finding.rule,
            "severity": finding.severity.value,
            "weight": int(weights.get(finding.severity.value, 0)),
            "damped_weight": round(damped_by_finding.get(finding.id, 0.0), 2),
            "title": finding.title,
        }
        for finding in items
    ]

    # Per-user: split each finding's weight across named users, then apply
    # the same decay (within user) + asymptote.
    user_shares: dict[str, list[tuple[str, float]]] = {}
    for finding in items:
        weight = int(weights.get(finding.severity.value, 0))
        if weight == 0:
            continue
        attributed = extract_users(f"{finding.title} {finding.description}")
        if not attributed:
            continue
        share = weight / len(attributed)
        for user in attributed:
            user_shares.setdefault(user, []).append((finding.id, share))

    users_out: dict[str, dict] = {}
    for user, shares in sorted(user_shares.items()):
        decayed = _decay_sorted((share for _fid, share in shares), decay)
        # Align decayed values back to their finding ids (same sort order).
        order = sorted(range(len(shares)), key=lambda i: -shares[i][1])
        damped_by_user_finding = {
            shares[i][0]: decayed[rank] for rank, i in enumerate(order)
        }
        user_rows = [
            {
                "finding_id": fid,
                "rule": next(f.rule for f in items if f.id == fid),
                "severity": next(f.severity.value for f in items if f.id == fid),
                "weight": round(share, 2),
                "damped_weight": round(damped_by_user_finding[fid], 2),
                "title": next(f.title for f in items if f.id == fid),
            }
            for fid, share in shares
        ]
        users_out[user] = {
            "score": _asymptote_score(sum(damped_by_user_finding.values()), cap),
            "findings": len(shares),
            "raw_score": round(sum(share for _fid, share in shares), 2),
            "breakdown": sorted(
                user_rows, key=lambda row: (-row["damped_weight"], row["rule"], row["finding_id"])
            ),
        }

    return {
        "hosts": {
            host: {
                "raw_score": raw_total,
                "score": score,
                "cap": cap,
                "decay": decay,
                "damped_total": round(damped_total, 2),
                "by_severity": dict(sorted(by_severity.items())),
                "breakdown": sorted(
                    breakdown,
                    key=lambda row: (-row["damped_weight"], row["rule"], row["finding_id"]),
                ),
            }
        },
        "users": users_out,
        "weights": dict(sorted(weights.items())),
        "method": METHOD,
    }
