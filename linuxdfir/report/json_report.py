"""findings.json writer (shadow-hash redacted)."""

from __future__ import annotations

import json
from pathlib import Path

from ..schema import Finding
from .sanitize import redact_shadow_hashes


def finding_to_redacted_dict(finding: Finding) -> dict:
    data = finding.to_dict()
    for key in ("title", "description"):
        data[key] = redact_shadow_hashes(data[key])
    return data


def write_findings(findings: list[Finding], path: str | Path) -> Path:
    target = Path(path)
    target.write_text(
        json.dumps([finding_to_redacted_dict(finding) for finding in findings], indent=2) + "\n",
        encoding="utf-8",
    )
    return target
