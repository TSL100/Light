"""Executable/hidden artifacts in world-writable scratch directories.

Files in /tmp, /var/tmp and /dev/shm that carry the exec bit, sit in a
hidden path, or whose archived content is an ELF binary are treated as
suspicious tooling until proven otherwise (droppers, preload libs,
reverse-shell binaries). Mode bits alone are unreliable on some evidence sources
(Windows-collected fixtures show 0666), so hidden-path and ELF-magic
signals carry equal weight. Benign empty placeholder files are
allowlisted via detection.toml.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath

from ..config import load_config
from ..parsers.filesystem_suspicious import parse_fs_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "executables_in_dev_shm"

USES_CONFIG = True

RULE_INFO = {
    RULE: {
        "why": (
            "World-writable directories are a staging area: droppers, "
            "preload libraries and reverse-shell binaries land there precisely because "
            "nothing enforces what is executed from them."
        ),
        "next_steps": [
            "Identify how the file arrived (shell history, web logs, package scripts, cron).",
            "Hash the file and check it against known-good baselines or threat intel.",
            "Check whether it is still running or referenced by persistence (cron, systemd, ld.so.preload).",
            "Remove the file and harden the directory (noexec mount, tmpfs permissions).",
        ],
    },
}


def _mode_exec(mode: str | None) -> bool:
    if not mode:
        return False
    try:
        return bool(int(mode, 8) & 0o111)
    except ValueError:
        return False


def _hidden_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(part.startswith(".") and part not in (".", "..") for part in parts[1:])


def _reasons(fields: dict, tags: list[str]) -> list[str]:
    reasons = []
    if _mode_exec(fields.get("mode")):
        reasons.append("exec-bit")
    if _hidden_path(fields.get("path", "")):
        reasons.append("hidden-path")
    if "elf" in tags:
        reasons.append("elf-content")
    return reasons


def detect(events: Iterable[Event], config: dict | None = None) -> list[Finding]:
    cfg = config if config is not None else load_config()
    scratch_cfg = cfg.get("scratch_exec", {})
    allowlist = {name.lower() for name in scratch_cfg.get("allowlist", [])}
    findings: list[Finding] = []
    for event in events:
        if event.event_type != "tmp_area_file":
            continue
        fields = parse_fs_message(event.message)
        if fields is None:
            continue
        if fields.get("type", "file") != "file":
            continue
        name = PurePosixPath(fields.get("path", "")).name.lower()
        if name in allowlist:
            continue
        reasons = _reasons(fields, event.tags)
        if not reasons:
            continue
        path = fields.get("path", "?")
        findings.append(
            Finding(
                id=make_finding_id(RULE, path, ",".join(reasons)),
                rule=RULE,
                severity=Severity.HIGH,
                title=f"Suspicious file in scratch directory: {path} ({', '.join(reasons)})",
                description=(
                    f"{path} lives in a world-writable scratch directory and shows "
                    f"{', '.join(reasons)} (mode={fields.get('mode', '?')}, "
                    f"uid={fields.get('uid', '?')}, size={fields.get('size', '?')}). "
                    "Legitimate software rarely executes from here."
                ),
                mitre_ids=["T1105"],
                first_seen=event.timestamp_utc,
                count=1,
                refs=[Ref(event.evidence_path, event.line_or_offset)],
            )
        )
    return findings
