"""Recently modified files under sensitive system paths.

Cron dirs, sudoers.d, ld.so.preload, systemd units and profile.d are
where persistence lives; a recent change there is a hunt trigger even
when the filename looks ordinary. Package-manager files inside cron
dirs (apt-compat, logrotate, placeholders) are allowlisted by name via
detection.toml [recent_changes]. Severity is HIGH for cron, sudoers,
ld.so.preload and systemd; MEDIUM for profile.d and other configured
paths.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath

from ..config import load_config
from ..parsers.filesystem_suspicious import parse_fs_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "recent_changes_in_sensitive_paths"

USES_CONFIG = True

RULE_INFO = {
    RULE: {
        "why": (
            "Persistence implants are written into cron, systemd, sudoers, ld.so "
            "and shell profiles; a recent mtime there is the cheapest signal that "
            "something changed privilege behavior."
        ),
        "next_steps": [
            "Diff the file against the package version (dpkg -V, rpm -V) or a backup.",
            "Check whether the referenced script/binary still exists and is trusted.",
            "Correlate the mtime with shell history, audit logs and login sessions.",
            "Remove unauthorized persistence and rotate credentials it may capture.",
        ],
    },
}

HIGH_PREFIXES = (
    "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
    "/etc/cron.weekly/", "/etc/cron.monthly/",
    "/etc/sudoers.d/",
    "/etc/ld.so.preload",
    "/etc/systemd/system/",
)

MITRE_BY_PATH = [
    ("/etc/cron.d/", "T1053.003"),
    ("/etc/cron.daily/", "T1053.003"),
    ("/etc/cron.hourly/", "T1053.003"),
    ("/etc/cron.weekly/", "T1053.003"),
    ("/etc/cron.monthly/", "T1053.003"),
    ("/etc/sudoers.d/", "T1548.003"),
    ("/etc/ld.so.preload", "T1574.006"),
    ("/etc/systemd/system/", "T1543.002"),
    ("/etc/profile.d/", "T1546.004"),
]


def _mitre_for(path: str) -> str:
    for prefix, technique in MITRE_BY_PATH:
        if path.startswith(prefix):
            return technique
    return "T1543.002"


def detect(events: Iterable[Event], config: dict | None = None) -> list[Finding]:
    cfg = config if config is not None else load_config()
    changes_cfg = cfg.get("recent_changes", {})
    paths = tuple(changes_cfg.get("paths", []))
    allowlist = {name.lower() for name in changes_cfg.get("allowlist_names", [])}
    findings: list[Finding] = []
    for event in events:
        if event.event_type != "recent_file":
            continue
        fields = parse_fs_message(event.message)
        if fields is None:
            continue
        path = fields.get("path", "")
        if not path or not path.startswith(paths):
            continue
        if PurePosixPath(path).name.lower() in allowlist:
            continue
        severity = (
            Severity.HIGH if path.startswith(HIGH_PREFIXES) else Severity.MEDIUM
        )
        mtime = fields.get("mtime_utc", "unknown")
        findings.append(
            Finding(
                id=make_finding_id(RULE, path),
                rule=RULE,
                severity=severity,
                title=f"Recent change in sensitive path: {path}",
                description=(
                    f"{path} (type={fields.get('type', 'file')}, "
                    f"mode={fields.get('mode', '?')}, uid={fields.get('uid', '?')}) "
                    f"was modified at {mtime}. Files under cron, sudoers, ld.so.preload, "
                    "systemd and profile.d implement privilege and persistence; a "
                    "recent change there is a hunt trigger even when the name looks "
                    "ordinary."
                ),
                mitre_ids=[_mitre_for(path)],
                first_seen=event.timestamp_utc,
                count=1,
                refs=[Ref(event.evidence_path, event.line_or_offset)],
            )
        )
    return findings
