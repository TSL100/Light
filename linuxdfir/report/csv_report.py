"""findings.csv writer (formula-neutralized, shadow-hash redacted)."""

from __future__ import annotations

import csv
from pathlib import Path

from ..schema import Finding, Ref
from .sanitize import sanitize_cell

CSV_HEADER = [
    "id",
    "rule",
    "severity",
    "title",
    "description",
    "mitre_ids",
    "first_seen",
    "last_seen",
    "count",
    "refs",
]


def _refs_cell(refs: list[Ref]) -> str:
    return "; ".join(
        f"{ref.evidence_path}:{ref.line_or_offset if ref.line_or_offset is not None else ''}" for ref in refs
    )


def finding_to_row(finding: Finding) -> list:
    data = finding.to_dict()
    return [
        sanitize_cell(data["id"]),
        sanitize_cell(data["rule"]),
        sanitize_cell(data["severity"]),
        sanitize_cell(data["title"]),
        sanitize_cell(data["description"]),
        sanitize_cell(";".join(data["mitre_ids"])),
        sanitize_cell(data["first_seen"] or ""),
        sanitize_cell(data["last_seen"] or ""),
        data["count"],
        sanitize_cell(_refs_cell(finding.refs)),
    ]


def write_csv(findings: list[Finding], path: str | Path) -> Path:
    target = Path(path)
    with open(target, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_HEADER)
        for finding in findings:
            writer.writerow(finding_to_row(finding))
    return target
