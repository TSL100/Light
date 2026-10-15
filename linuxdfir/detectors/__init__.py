"""Detectors: pure functions over the normalized event stream.

Each module exposes ``detect(events, ...) -> list[Finding]`` and a
``RULE_INFO`` mapping rule IDs to analyst guidance (why it matters plus
next steps) consumed by the HTML report.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..schema import Event, Finding
from . import (
    account_changes,
    audit_exec,
    executables_in_dev_shm,
    kernel_module,
    ld_preload,
    login_anomalies,
    masked_services,
    offensive_tools,
    package_install,
    recent_changes_in_sensitive_paths,
    remote_access,
    ssh_bruteforce,
    ssh_keys,
    sshd_weakening,
    suspicious_containers,
    suspicious_history,
    suspicious_processes,
    timestomp_detection,
    tmp_persistence,
    unusual_suid,
    webshell,
)

DETECTOR_MODULES = (
    ssh_bruteforce,
    suspicious_history,
    account_changes,
    tmp_persistence,
    ld_preload,
    ssh_keys,
    masked_services,
    sshd_weakening,
    webshell,
    package_install,
    audit_exec,
    login_anomalies,
    kernel_module,
    remote_access,
    timestomp_detection,
    offensive_tools,
    executables_in_dev_shm,
    suspicious_processes,
    unusual_suid,
    recent_changes_in_sensitive_paths,
    suspicious_containers,
)

RULE_INFO: dict[str, dict] = {}
for _module in DETECTOR_MODULES:
    RULE_INFO.update(getattr(_module, "RULE_INFO", {}))


def detect_all(events: Iterable[Event], config: dict | None = None) -> list[Finding]:
    """Run every detector over the event stream.

    ``events`` may be a list (shared across detectors) or a re-iterable
    stream object (each detector gets its own pass, keeping peak memory
    bounded on huge evidence).
    """
    findings: list[Finding] = []
    for module in DETECTOR_MODULES:
        if getattr(module, "USES_CONFIG", False):
            findings.extend(module.detect(events, config=config))
        else:
            findings.extend(module.detect(events))
    return findings
