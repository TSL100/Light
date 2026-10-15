"""Timestomping detection from ctime/mtime divergence and file cohorts.

Rule 1: a file whose ctime is more than ``threshold_days`` after its mtime
was touched without updating the modification stamp (cp -p, rsync -a, tar
extraction, or explicit timestomping). Scratch-path files are HIGH (a
future-looking mtime on a dropper is unusual); other paths are LOW and
describe the legitimate sources that produce this pattern.

Rule 2: within one directory, a file whose mtime is more than
``threshold_days`` older than the newest sibling is a cohort outlier.
Relative to sibling mtimes (not wall clock) so the rule stays stable on
aged evidence.

Noise paths are never skipped: log-rotation-style names under /var/log and
configured provenance prefixes (``[timestomp] allowlist_paths`` — package
and cache areas) lower the finding to INFO, and the finding text states the
exact provenance condition (path pattern + owner uid) that lowered it, so
the analyst can audit the downgrade instead of silently losing the signal.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath

from ..config import load_config
from ..parsers.filesystem_suspicious import parse_fs_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "timestomp_detection"

USES_CONFIG = True

RULE_INFO = {
    RULE: {
        "why": (
            "Backdating file timestamps (T1070.006) blends payloads into normal "
            "timelines. Package installs, archive extraction and log rotation "
            "produce the same ctime/mtime gaps, so severity separates unusual "
            "cases (scratch-space files, unexplained gaps) from provenance-"
            "explained ones (rotation names, package/cache paths), which are "
            "reported as INFO with the lowering condition stated in the text."
        ),
        "next_steps": [
            "Compare the file's mtime against package manager history and backup logs.",
            "Check shell history, audit logs and process executions around the ctime.",
            "For HIGH findings, treat the file as hostile: quarantine and re-image if unexplained.",
            "For LOW/INFO findings, verify the stated provenance (owner, rotation name, "
            "package path) before dismissing.",
        ],
    },
}

ROTATED_LOG_RE = re.compile(r"(\.\d+(\.gz)?|-\d{8})$")
SCRATCH_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
FS_EVENT_TYPES = ("recent_file", "tmp_area_file", "hidden_file", "suid_sgid_file")
VAR_LOG_PREFIX = "/var/log/"


def _rotation_noise_reason(path: str) -> str | None:
    """Return the provenance reason this path looks like logrotate output."""
    if not path.startswith(VAR_LOG_PREFIX):
        return None
    name = path.rsplit("/", 1)[-1]
    if name.endswith("~"):
        return "name ends with '~' (editor/rotation backup suffix)"
    match = ROTATED_LOG_RE.search(name)
    if match:
        return f"name ends with rotation suffix {match.group(0)!r}"
    return None


def _matched_allow_prefix(path: str, allowlist: tuple[str, ...]) -> str | None:
    for prefix in allowlist:
        if path.startswith(prefix):
            return prefix
    return None


def _provenance_note(fields: dict, reason: str) -> str:
    uid = fields.get("uid", "?")
    gid = fields.get("gid", "?")
    return (
        f" Provenance condition that lowers severity to INFO: {reason}; "
        f"file owner uid={uid} gid={gid}."
    )


def _parse_stamps(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=UTC)
    except ValueError:
        return None


def _gap_rule(
    event: Event,
    fields: dict,
    threshold: timedelta,
    allowlist: tuple[str, ...] = (),
) -> Finding | None:
    mtime = _parse_stamps(fields.get("mtime_utc"))
    ctime = _parse_stamps(fields.get("ctime_utc"))
    if mtime is None or ctime is None:
        return None
    gap = (ctime - mtime).total_seconds()
    if gap < threshold.total_seconds():
        return None
    path = fields.get("path", "?")
    days = gap / 86400
    in_scratch = path.startswith(SCRATCH_DIRS)
    severity = Severity.HIGH if in_scratch else Severity.LOW
    lowered_reason = None
    rotation_reason = _rotation_noise_reason(path)
    allow_prefix = _matched_allow_prefix(path, allowlist)
    if rotation_reason is not None:
        severity = Severity.INFO
        lowered_reason = (
            f"path is under {VAR_LOG_PREFIX} with a log-rotation-style name "
            f"({rotation_reason}), and logrotate-style ownership of spooled "
            "logs explains the timestamp gap"
        )
    elif allow_prefix is not None:
        severity = Severity.INFO
        lowered_reason = (
            f"path starts with configured provenance prefix {allow_prefix!r} "
            "(package/cache area where package-manager writes are expected)"
        )
    if in_scratch:
        description = (
            f"{path} in a world-writable scratch directory has mtime {mtime:%Y-%m-%d} "
            f"but ctime {ctime:%Y-%m-%d}, {days:.0f} days apart. The modification "
            "stamp being years behind the metadata update is inconsistent with "
            "normal installer behavior in scratch space."
        )
    else:
        description = (
            f"{path} has mtime {mtime:%Y-%m-%d} but ctime {ctime:%Y-%m-%d} "
            f"({days:.0f} days apart). Copying with preserved timestamps "
            "(cp -p, rsync -a, tar extraction) or explicit timestomping produces "
            "this gap; benign package installs are the most common source."
        )
    if lowered_reason is not None:
        description += _provenance_note(fields, lowered_reason)
    return Finding(
        id=make_finding_id(RULE, "gap", path),
        rule=RULE,
        severity=severity,
        title=f"Timestomp indicator: {path} (ctime {days:.0f}d after mtime)",
        description=description,
        mitre_ids=["T1070.006"],
        first_seen=event.timestamp_utc,
        count=1,
        refs=[Ref(event.evidence_path, event.line_or_offset)],
    )


def _cohort_rule(
    fs_events: list[tuple[Event, dict]],
    threshold: timedelta,
    allowlist: tuple[str, ...] = (),
) -> list[Finding]:
    by_dir: dict[str, list[tuple[Event, dict, datetime]]] = {}
    for event, fields in fs_events:
        path = fields.get("path", "")
        mtime = _parse_stamps(fields.get("mtime_utc"))
        if not path or mtime is None:
            continue
        parent = str(PurePosixPath(path).parent)
        by_dir.setdefault(parent, []).append((event, fields, mtime))
    findings: list[Finding] = []
    for parent, members in sorted(by_dir.items()):
        if len(members) < 3:
            continue
        newest = max(mt for _, _, mt in members)
        cutoff = newest - threshold
        for ev, fld, mt in members:
            if mt >= cutoff:
                continue
            path = fld.get("path", "?")
            behind = (newest - mt).total_seconds() / 86400
            severity = Severity.LOW
            lowered_reason = None
            name = PurePosixPath(path).name
            rotation_match = ROTATED_LOG_RE.search(name)
            if parent == "/var/log":
                severity = Severity.INFO
                lowered_reason = (
                    "directory is /var/log, where log rotation routinely "
                    "produces sibling-mtime spread"
                )
            elif rotation_match is not None:
                severity = Severity.INFO
                lowered_reason = (
                    f"name ends with rotation suffix {rotation_match.group(0)!r}, "
                    "consistent with logrotate output"
                )
            else:
                allow_prefix = _matched_allow_prefix(path, allowlist)
                if allow_prefix is not None:
                    severity = Severity.INFO
                    lowered_reason = (
                        f"path starts with configured provenance prefix "
                        f"{allow_prefix!r} (package/cache area)"
                    )
            description = (
                f"{path} in {parent} has mtime {mt:%Y-%m-%d}, {behind:.0f} days "
                "older than the most recently modified sibling in the same "
                "directory. Long-lived configuration or package files produce "
                "this pattern legitimately; treat as low-signal drift unless "
                "other indicators align."
            )
            if lowered_reason is not None:
                description += _provenance_note(fld, lowered_reason)
            findings.append(
                Finding(
                    id=make_finding_id(RULE, "cohort", path),
                    rule=RULE,
                    severity=severity,
                    title=f"Cohort timestomp outlier: {path} (mtime {mt:%Y-%m-%d})",
                    description=description,
                    mitre_ids=["T1070.006"],
                    first_seen=ev.timestamp_utc,
                    count=1,
                    refs=[Ref(ev.evidence_path, ev.line_or_offset)],
                )
            )
    return findings


def detect(events: Iterable[Event], config: dict | None = None) -> list[Finding]:
    cfg = config if config is not None else load_config()
    timestomp_cfg = cfg.get("timestomp", {})
    threshold_days = float(timestomp_cfg.get("threshold_days", 1))
    allowlist_paths = tuple(timestomp_cfg.get("allowlist_paths", ()))
    threshold = timedelta(days=threshold_days)
    fs_events: list[tuple[Event, dict]] = []
    for event in events:
        if event.event_type not in FS_EVENT_TYPES:
            continue
        fields = parse_fs_message(event.message)
        if fields is None or not fields.get("path"):
            continue
        fs_events.append((event, fields))
    best_gap: dict[str, Finding] = {}
    for event, fields in fs_events:
        finding = _gap_rule(event, fields, threshold, allowlist_paths)
        if finding is None:
            continue
        path = fields.get("path", "?")
        existing = best_gap.get(path)
        if existing is None or finding.severity.value > existing.severity.value:
            best_gap[path] = finding
    findings = list(best_gap.values())
    findings.extend(_cohort_rule(fs_events, threshold, allowlist_paths))
    return findings
