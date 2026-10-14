"""Transparent risk scoring: per-host and per-user, with breakdowns.

Host score = sum of per-finding severity weights (``[scoring] weights``),
capped at ``[scoring] cap``. Per-user scores attribute each finding's
weight to every username named in its title/description, split evenly so
one finding cannot be double-counted across users. Every contributing
finding is listed in the breakdown — the number is never a black box.
"""

from __future__ import annotations

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

METHOD = (
    "sum of per-finding severity weights, capped; per-user score splits "
    "each finding's weight across usernames named in its title/description"
)


def _most_common_host(events: Iterable[Event]) -> str | None:
    counts: Counter[str] = Counter()
    for event in events:
        if event.host:
            counts[event.host] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


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
    cap = int(scoring_cfg.get("cap", DEFAULT_CAP))

    if host is None and events is not None:
        host = _most_common_host(events)
    host = host or "unknown"

    breakdown: list[dict] = []
    by_severity: dict[str, int] = {}
    raw_total = 0
    user_scores: dict[str, dict] = {}

    for finding in findings:
        weight = int(weights.get(finding.severity.value, 0))
        raw_total += weight
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
        breakdown.append(
            {
                "finding_id": finding.id,
                "rule": finding.rule,
                "severity": finding.severity.value,
                "weight": weight,
                "title": finding.title,
            }
        )
        if weight == 0:
            continue
        attributed = extract_users(f"{finding.title} {finding.description}")
        if not attributed:
            continue
        share = weight / len(attributed)
        for user in attributed:
            entry = user_scores.setdefault(
                user, {"score": 0.0, "findings": 0, "breakdown": []}
            )
            entry["score"] += share
            entry["findings"] += 1
            entry["breakdown"].append(
                {
                    "finding_id": finding.id,
                    "rule": finding.rule,
                    "severity": finding.severity.value,
                    "weight": round(share, 2),
                    "title": finding.title,
                }
            )

    for entry in user_scores.values():
        entry["score"] = round(entry["score"], 2)

    return {
        "hosts": {
            host: {
                "raw_score": raw_total,
                "score": min(raw_total, cap),
                "cap": cap,
                "by_severity": by_severity,
                "breakdown": sorted(breakdown, key=lambda row: -row["weight"]),
            }
        },
        "users": user_scores,
        "weights": weights,
        "method": METHOD,
    }
