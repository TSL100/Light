"""Chain of custody: record how an analysis was performed.

`analysis_log.json` captures tool version, input SHA256, command line,
analyst machine, start/end times, parser/detector inventory and the
config hash, so a report can be tied back to exact inputs and settings.
Evidence is never modified by the analyzer (read-only opens only).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .detectors import DETECTOR_MODULES

CHUNK = 1024 * 1024
SCHEMA = "linuxdfir.analysis_log/1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def config_sha256(config: dict) -> str:
    canonical = json.dumps(config, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def detector_rules() -> list[str]:
    rules: set[str] = set()
    for module in DETECTOR_MODULES:
        rules.update(getattr(module, "RULE_INFO", {}))
    return sorted(rules)


def write_analysis_log(
    outdir: Path,
    *,
    argv: list[str],
    evidence_source: str | Path,
    evidence_kind: str,
    input_sha256: str | None,
    started_utc: datetime,
    ended_utc: datetime,
    config: dict | None,
    config_source: str | None,
    parser_names: list[str],
    exit_code: int | None = None,
    extra: dict | None = None,
) -> Path:
    """Write analysis_log.json into outdir and return its path."""
    duration = (ended_utc - started_utc).total_seconds()
    entry: dict = {
        "schema": SCHEMA,
        "tool": {
            "name": "linuxdfir",
            "version": __version__,
            "python": platform.python_version(),
        },
        "command_line": list(argv),
        "analyst_machine": {
            "hostname": platform.node(),
            "system": platform.system(),
            "release": platform.release(),
        },
        "input": {
            "source": str(evidence_source),
            "kind": evidence_kind,
            "sha256": input_sha256,
        },
        "started_utc": started_utc.astimezone(UTC).isoformat(),
        "ended_utc": ended_utc.astimezone(UTC).isoformat(),
        "duration_seconds": round(duration, 3),
        "parsers": {"count": len(parser_names), "names": list(parser_names)},
        "detectors": {"count": len(detector_rules()), "rules": detector_rules()},
        "config": {
            "source": config_source or "shipped detection.toml",
            "sha256": config_sha256(config) if config is not None else None,
        },
        "evidence_modified": False,
        "exit_code": exit_code,
    }
    if extra:
        entry["extra"] = extra
    target = outdir / "analysis_log.json"
    payload = json.dumps(entry, indent=2, sort_keys=False) + "\n"
    tmp = target.with_name(target.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, target)
    return target


def input_fingerprint(evidence_source: str | Path) -> tuple[str, str | None]:
    """Return (kind, sha256) for an evidence path without modifying it."""
    path = Path(evidence_source)
    if path.is_file():
        return "archive", sha256_file(path)
    if path.is_dir():
        manifest = path / "manifest.json"
        if manifest.is_file():
            return "folder", sha256_file(manifest)
        return "folder", None
    return "missing", None


def current_argv(argv: list[str] | None) -> list[str]:
    if argv is not None:
        return ["linuxdfir", *argv]
    return list(sys.argv)
