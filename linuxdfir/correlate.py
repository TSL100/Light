"""Attack-chain correlation: link findings by shared entities and time.

Findings are nodes; an edge exists when two findings share an external
IP, a filesystem path, or a rare username (users appearing in at most
``[correlation] rare_user_max_findings`` findings — common accounts like
root would otherwise collapse everything into one hairball). Connected
components with at least ``min_chain_length`` findings become chains.
Steps are ordered by MITRE tactic stage, then by first_seen (undated
steps sort before dated ones inside the same stage) so the narrative
reads access → execution → persistence → post-exploitation.

Confidence is transparent: ``min(0.95, 0.4 + 0.15*kinds + 0.05*steps)``
where ``kinds`` is how many entity types (ip/path/user) produced links.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime

from .iocs import extract_ips, extract_paths, extract_users
from .mitre import TACTIC_ORDER, tactic_name, tactics_for
from .schema import Finding

_TACTIC_INDEX = {tid: index for index, (tid, _) in enumerate(TACTIC_ORDER)}
_STAGE_UNKNOWN = len(TACTIC_ORDER)


class _UnionFind:
    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, node: int) -> int:
        while self._parent[node] != node:
            self._parent[node] = self._parent[self._parent[node]]
            node = self._parent[node]
        return node

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self._parent[right_root] = left_root


def entities_for_finding(finding: Finding) -> dict:
    text = f"{finding.title} {finding.description}"
    return {
        "ips": set(extract_ips(text)),
        "paths": set(extract_paths(text)),
        "users": set(extract_users(text)),
    }


def stage_rank(finding: Finding) -> int:
    ranks = [
        _TACTIC_INDEX[tactic]
        for mid in finding.mitre_ids
        for tactic in tactics_for(mid)
        if tactic in _TACTIC_INDEX
    ]
    return min(ranks) if ranks else _STAGE_UNKNOWN


def step_sort_key(finding: Finding) -> tuple:
    return (
        stage_rank(finding),
        0 if finding.first_seen is None else 1,
        finding.first_seen or datetime.min.replace(tzinfo=UTC),
    )


def _confidence(chain_kinds: set[str], step_count: int) -> float:
    return round(min(0.95, 0.4 + 0.15 * len(chain_kinds) + 0.05 * min(step_count, 4)), 2)


def _confidence_label(value: float) -> str:
    if value >= 0.75:
        return "high"
    if value >= 0.55:
        return "medium"
    return "low"


def _shorten(title: str, limit: int = 70) -> str:
    return title if len(title) <= limit else title[: limit - 1] + "…"


def _chain_tactics(steps: list[Finding]) -> list[str]:
    seen: dict[str, None] = {}
    for finding in steps:
        for mid in finding.mitre_ids:
            for tactic in tactics_for(mid):
                seen.setdefault(tactic, None)
    return [tid for tid, _ in TACTIC_ORDER if tid in seen]


def correlate_findings(
    findings: Iterable[Finding],
    config: dict | None = None,
) -> dict:
    """Build attack chains plus overall tactic coverage from findings."""
    corr_cfg = (config or {}).get("correlation", {}) or {}
    min_len = int(corr_cfg.get("min_chain_length", 2))
    rare_max = int(corr_cfg.get("rare_user_max_findings", 5))

    items = list(findings)
    entities = [entities_for_finding(finding) for finding in items]
    user_rarity: Counter[str] = Counter()
    for entry in entities:
        for user in entry["users"]:
            user_rarity[user] += 1

    uf = _UnionFind(len(items))
    edge_kinds: dict[tuple[int, int], set[str]] = {}
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            kinds: set[str] = set()
            if entities[i]["ips"] & entities[j]["ips"]:
                kinds.add("ip")
            if entities[i]["paths"] & entities[j]["paths"]:
                kinds.add("path")
            shared_users = {
                user
                for user in entities[i]["users"] & entities[j]["users"]
                if user_rarity[user] <= rare_max
            }
            if shared_users:
                kinds.add("user")
            if kinds:
                uf.union(i, j)
                edge_kinds[(i, j)] = kinds

    components: dict[int, list[int]] = {}
    for index in range(len(items)):
        components.setdefault(uf.find(index), []).append(index)

    chains: list[dict] = []
    unchained: list[str] = []
    for indexes in components.values():
        if len(indexes) < min_len:
            unchained.extend(items[i].id for i in indexes)
            continue
        chain_kinds: set[str] = set()
        for i in indexes:
            for j in indexes:
                chain_kinds |= edge_kinds.get((min(i, j), max(i, j)), set())
        steps = sorted((items[i] for i in indexes), key=step_sort_key)
        chain_id = hashlib.sha256(
            "|".join(sorted(item.id for item in steps)).encode("utf-8")
        ).hexdigest()[:12]
        tactic_ids = _chain_tactics(steps)
        confidence = _confidence(chain_kinds, len(steps))
        joined = " → ".join(_shorten(item.title) for item in steps[:6])
        if len(steps) > 6:
            joined += " …"
        chains.append(
            {
                "id": chain_id,
                "confidence": confidence,
                "confidence_label": _confidence_label(confidence),
                "link_kinds": sorted(chain_kinds),
                "entities": {
                    "ips": sorted(set().union(*(entities[i]["ips"] for i in indexes))),
                    "paths": sorted(set().union(*(entities[i]["paths"] for i in indexes))),
                    "users": sorted(set().union(*(entities[i]["users"] for i in indexes))),
                },
                "steps": [
                    {
                        "finding_id": item.id,
                        "rule": item.rule,
                        "severity": item.severity.value,
                        "title": item.title,
                        "first_seen": item.first_seen.isoformat() if item.first_seen else None,
                    }
                    for item in steps
                ],
                "narrative": (
                    f"{len(steps)} linked findings via {', '.join(sorted(chain_kinds))}: {joined}"
                ),
                "tactic_ids": tactic_ids,
                "tactic_names": [tactic_name(tid) for tid in tactic_ids],
            }
        )
    chains.sort(key=lambda chain: (-chain["confidence"], chain["id"]))

    coverage: dict[str, dict] = {}
    for finding in items:
        for mid in finding.mitre_ids:
            for tactic in tactics_for(mid):
                row = coverage.setdefault(
                    tactic, {"tactic_id": tactic, "finding_count": 0, "rules": []}
                )
                row["finding_count"] += 1
                if finding.rule not in row["rules"]:
                    row["rules"].append(finding.rule)
    tactic_coverage = [
        {
            "tactic_id": tid,
            "name": tactic_name(tid),
            "finding_count": coverage[tid]["finding_count"],
            "rules": sorted(coverage[tid]["rules"]),
        }
        for tid, _ in TACTIC_ORDER
        if tid in coverage
    ]

    return {
        "chains": chains,
        "tactic_coverage": tactic_coverage,
        "unchained_finding_ids": sorted(unchained),
    }
