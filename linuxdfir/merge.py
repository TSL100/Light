"""Post-detection pipeline: severity overrides, allowlist, cross-rule dedup.

Order matters: ``[severity_overrides]`` reweights findings before they
are scored, ``[allowlist] findings`` drops known-benign findings, then
``merge_duplicate_findings`` collapses overlapping rules that flagged the
same path at the same severity (sharing a MITRE technique) into a single
finding that retains every evidence ref from the originals.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import replace

from .schema import Finding, Ref, parse_severity, severity_rank

PATH_RE = re.compile(r"/[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)+")


def _primary_path(text: str) -> str | None:
    matches = PATH_RE.findall(text)
    return max(matches, key=len) if matches else None


def apply_severity_overrides(
    findings: Iterable[Finding],
    config: dict | None = None,
) -> list[Finding]:
    overrides = (config or {}).get("severity_overrides", {}) or {}
    if not overrides:
        return list(findings)
    out: list[Finding] = []
    for finding in findings:
        target = overrides.get(finding.rule)
        if target is not None:
            finding = replace(finding, severity=parse_severity(target))
        out.append(finding)
    return out


def apply_allowlist(
    findings: Iterable[Finding],
    config: dict | None = None,
) -> list[Finding]:
    """Drop findings matching any ``[allowlist] findings`` entry.

    Each entry is a table with required ``rule`` and optional
    ``title_contains`` / ``path`` matchers; an entry with only ``rule``
    suppresses every finding of that rule.
    """
    entries = (config or {}).get("allowlist", {}).get("findings", []) or []
    if not entries:
        return list(findings)
    out: list[Finding] = []
    for finding in findings:
        text = f"{finding.title} {finding.description}"
        drop = False
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            rule = entry.get("rule")
            if rule and rule != finding.rule:
                continue
            if entry.get("title_contains") and entry["title_contains"] not in finding.title:
                continue
            if entry.get("path") and entry["path"] not in text:
                continue
            drop = True
            break
        if not drop:
            out.append(finding)
    return out


def _merge_members(primary: Finding, members: list[Finding]) -> Finding:
    refs: list[Ref] = list(primary.refs)
    seen = {(ref.evidence_path, ref.line_or_offset) for ref in refs}
    rules = {primary.rule}
    count = primary.count
    first = primary.first_seen
    last = primary.last_seen
    mitre = list(primary.mitre_ids)
    notes: list[str] = []
    for finding in members:
        rules.add(finding.rule)
        count += finding.count
        for ref in finding.refs:
            key = (ref.evidence_path, ref.line_or_offset)
            if key not in seen:
                seen.add(key)
                refs.append(ref)
        if finding.first_seen and (first is None or finding.first_seen < first):
            first = finding.first_seen
        if finding.last_seen and (last is None or finding.last_seen > last):
            last = finding.last_seen
        for mid in finding.mitre_ids:
            if mid not in mitre:
                mitre.append(mid)
        notes.append(f"{finding.rule} ({finding.id})")
    other_rules = sorted(rules - {primary.rule})
    description = primary.description
    if other_rules:
        description += (
            " Merged duplicate finding(s) from rule(s): "
            + ", ".join(other_rules)
            + " (all evidence refs retained)."
        )
    return replace(
        primary,
        description=description,
        refs=refs,
        count=count,
        first_seen=first,
        last_seen=last,
        mitre_ids=mitre,
    )


def merge_duplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse same-path, same-severity findings across rules.

    Two findings merge when their titles/descriptions name the same
    filesystem path at the same severity AND they share at least one
    MITRE technique (or the same rule, for same-rule path duplicates).
    The survivor is the finding with the higher severity, then more
    refs, then the lexicographically smaller rule; every evidence ref
    and the merged counts are kept. Distinct signals (e.g. a timestomp
    and a tool-transfer finding for the same file) stay separate because
    their techniques differ.
    """
    groups: dict[tuple[str, str], list[Finding]] = {}
    ungrouped: list[Finding] = []
    for finding in findings:
        path = _primary_path(finding.title) or _primary_path(finding.description)
        if path is None:
            ungrouped.append(finding)
            continue
        groups.setdefault((path, finding.severity.value), []).append(finding)

    out: list[Finding] = list(ungrouped)
    for (_path, _severity), members in groups.items():
        if len(members) == 1:
            out.append(members[0])
            continue
        ordered = sorted(
            members,
            key=lambda f: (-severity_rank(f.severity), -len(f.refs), f.rule),
        )
        primary = ordered[0]
        group_techniques = set(primary.mitre_ids)
        merged_members: list[Finding] = []
        leftovers: list[Finding] = []
        for finding in ordered[1:]:
            if finding.rule == primary.rule or (set(finding.mitre_ids) & group_techniques):
                merged_members.append(finding)
                group_techniques |= set(finding.mitre_ids)
            else:
                leftovers.append(finding)
        if merged_members:
            out.append(_merge_members(primary, merged_members))
        else:
            out.append(primary)
        out.extend(leftovers)

    out.sort(key=lambda finding: (finding.rule, finding.title))
    return out


def postprocess_findings(
    findings: Iterable[Finding],
    config: dict | None = None,
) -> list[Finding]:
    """severity overrides → allowlist suppression → cross-rule dedup."""
    result = apply_severity_overrides(findings, config)
    result = apply_allowlist(result, config)
    result = merge_duplicate_findings(result)
    return result
