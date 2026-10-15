"""Optional YARA scanning of collected file contents.

YARA is an *optional* dependency (``pip install linuxdfir[yara]``). Everything
here lazy-imports ``yara`` so the core pipeline never requires it: when
yara-python is missing the scan is skipped cleanly with ``status: skipped``
instead of raising.

Rules come from a user-supplied folder of ``.yar`` / ``.yara`` files, compiled
once via ``yara.compile(filepaths=...)``. File bytes are read through the
``Evidence`` API (never extracted to disk), bounded by ``[yara].max_file_mb``.

Each (file, rule) hit becomes one ``yara_match`` Finding whose title names
the rule and whose refs point at the matched file. Rule metadata may tune the
finding: ``meta: severity = "critical"`` overrides the configured default,
and ``meta: mitre = "T1059, T1105"`` attaches MITRE IDs.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .config import load_config
from .schema import Finding, Ref, Severity, make_finding_id, parse_severity

if TYPE_CHECKING:  # pragma: no cover - import-time typing only
    from .ingest import Evidence

RULE = "yara_match"

RULE_INFO = {
    RULE: {
        "why": (
            "A YARA rule written for known malware, webshells or dual-use "
            "tooling matched the bytes of a collected file. Unlike "
            "name-based heuristics this is a content match, so treat it as "
            "a strong pivot: recover the file and confirm what it does."
        ),
        "next_steps": [
            "Recover the matched file from the evidence archive and detonate or dissect it off-host.",
            "Check how the file arrived and whether it is referenced by persistence (cron, systemd, history).",
            "Hunt the same rule across the rest of the fleet's evidence.",
            "Tune [yara] severity/max_file_mb in detection.toml if the rule is noisy in your environment.",
        ],
    },
}

RULE_EXTENSIONS = (".yar", ".yara")
DEFAULT_SEVERITY = Severity.HIGH
DEFAULT_MAX_FILE_MB = 16
_MAX_STRINGS_SHOWN = 10
_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class YaraUnavailable(Exception):
    """Raised when yara-python is not installed or has no usable API."""


def _import_yara() -> Any:
    """Lazy-import yara-python; never at module import time."""
    try:
        import yara  # noqa: PLC0415
    except ImportError as exc:
        raise YaraUnavailable(
            "yara-python is not installed; skipping YARA scan "
            "(install with: pip install linuxdfir[yara])"
        ) from exc
    if getattr(yara, "compile", None) is None:
        raise YaraUnavailable("installed yara module has no compile(); cannot scan")
    return yara


def _rule_files(rules_dir: str | Path) -> list[Path]:
    root = Path(rules_dir)
    if not root.is_dir():
        raise ValueError(f"YARA rules folder is not a directory: {root}")
    files = sorted(
        path for path in root.iterdir()
        if path.is_file() and path.suffix.lower() in RULE_EXTENSIONS
    )
    if not files:
        raise ValueError(f"no YARA rules (*.yar/*.yara) in: {root}")
    return files


def compile_rules(rules_dir: str | Path) -> tuple[Any, dict]:
    """Compile every .yar/.yara file in ``rules_dir``.

    Returns ``(compiled_rules, info)`` where info names the source files.
    Raises YaraUnavailable when yara-python is missing, ValueError for a bad
    folder or uncompilable rules.
    """
    yara = _import_yara()
    files = _rule_files(rules_dir)
    filepaths: dict[str, str] = {}
    for index, path in enumerate(files):
        namespace = path.stem or f"rules_{index}"
        if namespace in filepaths:
            namespace = f"{namespace}_{index}"
        filepaths[namespace] = str(path)
    try:
        compiled = yara.compile(filepaths=filepaths)
    except ImportError as exc:
        raise YaraUnavailable(f"yara failed to compile rules: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"cannot compile YARA rules in {Path(rules_dir)}: {exc}") from exc
    return compiled, {"rules_dir": str(Path(rules_dir)), "rules_files": [p.name for p in files]}


def _match_mitre(meta: dict) -> list[str]:
    raw = meta.get("mitre", "")
    if not isinstance(raw, str) or not raw.strip():
        return []
    return [token for token in re.split(r"[,\s]+", raw.strip()) if _MITRE_RE.match(token)]


def _match_severity(meta: dict, default: Severity) -> Severity:
    raw = meta.get("severity", "")
    if isinstance(raw, str) and raw.strip():
        try:
            return parse_severity(raw.strip())
        except ValueError:
            pass
    return default


def _string_summary(strings: Any) -> tuple[int, str]:
    """Return (hit_count, short 'id@offset, ...' summary) for a yara match."""
    items: list[str] = []
    count = 0
    try:
        iterable = list(strings or [])
    except TypeError:
        return 0, ""
    for entry in iterable:
        count += 1
        if len(items) >= _MAX_STRINGS_SHOWN:
            continue
        offset: Any = None
        identifier: Any = None
        if isinstance(entry, (tuple, list)) and len(entry) >= 2:
            offset, identifier = entry[0], entry[1]
        else:
            offset = getattr(entry, "offset", None)
            identifier = getattr(entry, "identifier", None)
        if identifier is None:
            identifier = "?"
        items.append(f"{identifier}@{offset}")
    summary = ", ".join(items)
    if count > len(items):
        summary += f" (+{count - len(items)} more)"
    return count, summary


def _default_severity(config: dict | None) -> Severity:
    raw = (config or {}).get("yara", {}).get("severity", DEFAULT_SEVERITY.value)
    try:
        return parse_severity(str(raw))
    except ValueError:
        return DEFAULT_SEVERITY


def _max_file_bytes(config: dict | None, override: int | None) -> int:
    if override is not None:
        return max(1, int(override)) * 1024 * 1024
    try:
        value = int((config or {}).get("yara", {}).get("max_file_mb", DEFAULT_MAX_FILE_MB))
    except (TypeError, ValueError):
        value = DEFAULT_MAX_FILE_MB
    return max(1, value) * 1024 * 1024


def _scan_targets(evidence: Evidence) -> list[dict]:
    """Manifest file records that hold scannable content (evidence/* members)."""
    targets = []
    for rec in evidence.manifest.get("files", []):
        archive_path = rec.get("archive_path")
        if not archive_path or not str(archive_path).startswith("evidence/"):
            continue
        if not rec.get("sha256"):
            continue  # metadata-only record: no content to scan
        targets.append(rec)
    return targets


def _count_contentless(evidence: Evidence) -> int:
    """Evidence members with no content hash (symlink/metadata-only records)."""
    count = 0
    for rec in evidence.manifest.get("files", []):
        archive_path = rec.get("archive_path")
        if archive_path and str(archive_path).startswith("evidence/") and not rec.get("sha256"):
            count += 1
    return count


def scan_evidence(
    evidence: Evidence,
    compiled: Any,
    *,
    config: dict | None = None,
    max_file_mb: int | None = None,
    rules_dir: str | Path | None = None,
    rules_files: list[str] | None = None,
) -> tuple[list[Finding], dict]:
    """Match compiled rules against every collected file with content."""
    from .ingest import EvidenceError  # noqa: PLC0415  (avoid import cycle)

    default_severity = _default_severity(config)
    size_cap = _max_file_bytes(config, max_file_mb)
    findings: list[Finding] = []
    stats: dict = {
        "status": "ok",
        "rules_dir": str(rules_dir) if rules_dir is not None else None,
        "rules_files": list(rules_files or []),
        "files_scanned": 0,
        "files_skipped_no_content": _count_contentless(evidence),
        "files_skipped_too_large": 0,
        "files_skipped_unreadable": 0,
        "matches": 0,
    }
    for rec in _scan_targets(evidence):
        member = rec["archive_path"]
        original = rec.get("original_path") or member
        try:
            blob = evidence.read_bytes(member, limit=size_cap + 1)
        except EvidenceError as exc:
            message = str(exc)
            if "exceeds size limit" in message:
                stats["files_skipped_too_large"] += 1
            else:
                stats["files_skipped_unreadable"] += 1
            continue
        if len(blob) > size_cap:
            stats["files_skipped_too_large"] += 1
            continue
        stats["files_scanned"] += 1
        try:
            matches = compiled.match(data=blob) or []
        except Exception:
            stats["files_skipped_unreadable"] += 1
            continue
        for match in matches:
            rule_name = str(getattr(match, "rule", "?") or "?")
            namespace = getattr(match, "namespace", "") or ""
            meta = getattr(match, "meta", None) or {}
            if not isinstance(meta, dict):
                meta = {}
            hit_count, summary = _string_summary(getattr(match, "strings", []))
            severity = _match_severity(meta, default_severity)
            source = f" (rules file '{namespace}')" if namespace else ""
            findings.append(
                Finding(
                    id=make_finding_id(RULE, rule_name, str(original)),
                    rule=RULE,
                    severity=severity,
                    title=f"YARA match: {rule_name} in {original}",
                    description=(
                        f"YARA rule {rule_name!r}{source} matched {original} "
                        f"({len(blob)} bytes): {max(hit_count, 1)} string hit(s)"
                        + (f" ({summary})" if summary else "")
                        + "."
                    ),
                    mitre_ids=_match_mitre(meta),
                    count=max(hit_count, 1),
                    refs=[Ref(str(original), None)],
                )
            )
            stats["matches"] += 1
    return findings, stats


def scan_with_rules_dir(
    evidence: Evidence,
    rules_dir: str | Path,
    config: dict | None = None,
    *,
    max_file_mb: int | None = None,
) -> tuple[list[Finding], dict]:
    """Compile ``rules_dir`` and scan; missing yara-python skips cleanly.

    Returns ``(findings, stats)``. When yara-python is absent the findings
    list is empty and ``stats["status"] == "skipped"`` with a human-readable
    ``reason``. A bad rules folder or uncompilable rules raise ValueError.
    """
    cfg = config if config is not None else load_config()
    try:
        compiled, info = compile_rules(rules_dir)
    except YaraUnavailable as exc:
        return [], {
            "status": "skipped",
            "reason": str(exc),
            "rules_dir": str(Path(rules_dir)),
            "rules_files": [],
            "files_scanned": 0,
            "files_skipped_no_content": 0,
            "files_skipped_too_large": 0,
            "files_skipped_unreadable": 0,
            "matches": 0,
        }
    return scan_evidence(
        evidence,
        compiled,
        config=cfg,
        max_file_mb=max_file_mb,
        rules_dir=info["rules_dir"],
        rules_files=info["rules_files"],
    )
