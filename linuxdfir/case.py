"""Multi-host cases: per-host runs plus cross-host overlap and a combined timeline.

A case analyzes several evidence archives into one folder::

    case/
      hosts/<hostname>/   full `run` output per host (verify/parse/detect/report)
      combined_timeline.db / .csv / combined_events.jsonl
      case.json            hosts, IOC overlap, timeline stats

Cross-host IOC overlap answers "same IP seen on several hosts": external
indicators (ip, domain, url, hash) from each host's ``iocs.json`` that occur
on two or more hosts. Internal indicators (paths, usernames) overlap
trivially on same-distro hosts and are excluded by design.

The combined timeline merges every host's ``events.jsonl`` into one
SQLite timeline plus CSV/JSONL exports; the ``host`` column already in the
schema keeps rows attributable.

No optional dependencies: stdlib only.
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path

from .schema import Event

OVERLAP_TYPES = ("ip", "domain", "url", "hash")
_MAX_OVERLAP = 1000

_HOST_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_host_dir(name: str | None, fallback: str) -> str:
    """Make a hostname safe as a single path component."""
    candidate = (name or "").strip() or fallback
    candidate = _HOST_SAFE_RE.sub("_", candidate).strip("._")
    return candidate or fallback


def unique_host_dir(hosts_root: Path, hostname: str | None, fallback: str) -> Path:
    """Pick hosts/<name>/, suffixing _2, _3… on collision (cloned hostnames)."""
    base = sanitize_host_dir(hostname, fallback)
    candidate = hosts_root / base
    counter = 2
    while candidate.exists():
        candidate = hosts_root / f"{base}_{counter}"
        counter += 1
    return candidate


def prepare_hosts_root(case_dir: Path) -> Path:
    """Create a fresh hosts/ directory; a case run rebuilds it every time."""
    hosts_root = Path(case_dir) / "hosts"
    if hosts_root.exists():
        shutil.rmtree(hosts_root)
    hosts_root.mkdir(parents=True, exist_ok=True)
    return hosts_root


def evidence_fallback_name(evidence: str | Path) -> str:
    """Filesystem-safe stem for an evidence path (used until hostname is known)."""
    name = Path(evidence).name
    lowered = name.lower()
    for suffix in (".tar.gz", ".tgz", ".tar"):
        if lowered.endswith(suffix):
            name = name[: -len(suffix)]
            break
    else:
        name = Path(name).stem
    return sanitize_host_dir(name, "host")


def read_host_iocs(host_dir: Path) -> list[dict]:
    """External overlap-eligible IOC entries from one host's iocs.json."""
    try:
        payload = json.loads((host_dir / "iocs.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    entries = []
    for bucket in ("external",):
        items = payload.get(bucket, []) if isinstance(payload, dict) else []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") not in OVERLAP_TYPES:
                continue
            value = entry.get("value")
            if not value:
                continue
            entries.append(entry)
    return entries


def compute_overlap(host_iocs: dict[str, list[dict]]) -> tuple[list[dict], dict]:
    """Find external indicators present on two or more hosts.

    Returns ``(overlap, stats)``; overlap sorted by host count desc, then
    type/value. Each entry names the indicator, the hosts, and the per-host
    source count.
    """
    by_indicator: dict[tuple[str, str], dict] = {}
    for host, entries in host_iocs.items():
        for entry in entries:
            key = (entry["type"], str(entry["value"]).lower())
            bucket = by_indicator.get(key)
            if bucket is None:
                bucket = {
                    "type": entry["type"],
                    "value": entry["value"],
                    "defanged": entry.get("defanged", entry["value"]),
                    "hosts": [],
                    "per_host": {},
                }
                by_indicator[key] = bucket
            if host not in bucket["per_host"]:
                bucket["hosts"].append(host)
            bucket["per_host"][host] = len(entry.get("sources", []) or [])
    overlap = []
    for bucket in by_indicator.values():
        if len(bucket["hosts"]) < 2:
            continue
        bucket["hosts"].sort()
        bucket["host_count"] = len(bucket["hosts"])
        overlap.append(bucket)
    overlap.sort(key=lambda item: (-item["host_count"], item["type"], str(item["value"]).lower()))
    stats = {"indicators_seen": len(by_indicator), "overlapping": len(overlap)}
    truncated = False
    if len(overlap) > _MAX_OVERLAP:
        overlap = overlap[:_MAX_OVERLAP]
        truncated = True
    stats["truncated"] = truncated
    return overlap, stats


def iter_host_events(host_dir: Path) -> Iterator[Event]:
    """Yield events from one host's events.jsonl, skipping bad lines."""
    path = host_dir / "events.jsonl"
    try:
        handle = open(path, encoding="utf-8")
    except OSError:
        return
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield Event.from_dict(json.loads(line))
            except (ValueError, KeyError, TypeError):
                continue


def _host_collection_time(host_dir: Path) -> datetime:
    try:
        manifest = json.loads((host_dir / "manifest.json").read_text(encoding="utf-8"))
        stamp = manifest.get("collection_time_utc")
        parsed = datetime.fromisoformat(stamp) if stamp else None
        if parsed is not None and parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed or datetime.now(UTC)
    except (OSError, ValueError):
        return datetime.now(UTC)


def build_combined_timeline(
    host_dirs: dict[str, Path],
    db_path: str | Path,
    csv_path: str | Path,
    jsonl_path: str | Path,
) -> dict:
    """Merge every host's events into one timeline db + csv + jsonl."""
    from .timeline import Timeline  # noqa: PLC0415 (heavy import, case-only path)

    def generate() -> Iterator[Event]:
        for _host in sorted(host_dirs):
            yield from iter_host_events(host_dirs[_host])

    collection_times = [_host_collection_time(path) for path in host_dirs.values()]
    latest = max(collection_times) if collection_times else datetime.now(UTC)
    timeline = Timeline.build(db_path, generate(), collection_time_utc=latest)
    with timeline:
        jsonl_rows = timeline.write_jsonl(jsonl_path)
        csv_rows = timeline.write_csv(csv_path)
        stats = timeline.stats()
    return {
        "hosts": sorted(host_dirs),
        "rows": csv_rows,
        "jsonl_rows": jsonl_rows,
        "dated": stats.get("dated", 0),
        "undated": stats.get("undated", 0),
        "collection_time_utc": latest.isoformat(),
    }


def summarize_host(host_dir: Path, evidence: str, exit_code: int) -> dict:
    """Per-host roll-up for case.json from a finished `run` directory."""
    summary: dict = {
        "evidence": evidence,
        "outdir": host_dir.name,
        "exit_code": exit_code,
        "hostname": None,
        "integrity_ok": None,
        "risk_score": None,
        "raw_score": None,
        "findings_total": 0,
        "findings_actionable": 0,
    }
    try:
        manifest = json.loads((host_dir / "manifest.json").read_text(encoding="utf-8"))
        summary["hostname"] = manifest.get("hostname")
    except (OSError, ValueError):
        pass
    try:
        verify = json.loads((host_dir / "verify_report.json").read_text(encoding="utf-8"))
        summary["integrity_ok"] = verify.get("integrity_ok")
    except (OSError, ValueError):
        pass
    try:
        findings = json.loads((host_dir / "findings.json").read_text(encoding="utf-8"))
        summary["findings_total"] = len(findings)
        summary["findings_actionable"] = sum(1 for f in findings if f.get("severity") != "info")
    except (OSError, ValueError):
        pass
    try:
        risk = json.loads((host_dir / "risk.json").read_text(encoding="utf-8"))
        hosts = risk.get("hosts", {})
        if hosts:
            _name, data = sorted(hosts.items())[0]
            summary["risk_score"] = data.get("score")
            summary["raw_score"] = data.get("raw_score")
    except (OSError, ValueError):
        pass
    return summary


def build_case_record(
    hosts: list[dict],
    overlap: list[dict],
    overlap_stats: dict,
    timeline_stats: dict,
    argv: list[str] | None = None,
) -> dict:
    """Assemble the case.json payload."""
    return {
        "schema": "linuxdfir/case/1",
        "created_utc": datetime.now(UTC).isoformat(),
        "command_line": list(argv or []),
        "hosts": hosts,
        "host_count": len(hosts),
        "overlap": overlap,
        "overlap_stats": overlap_stats,
        "timeline": timeline_stats,
    }


def iter_events_all(host_dirs: Iterable[Path]) -> Iterator[Event]:
    """Yield every host's events (helper for case-wide follow-up scans)."""
    for host_dir in host_dirs:
        yield from iter_host_events(host_dir)
