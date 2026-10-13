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
    ld_preload,
    masked_services,
    ssh_bruteforce,
    ssh_keys,
    sshd_weakening,
    suspicious_history,
    tmp_persistence,
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
)

RULE_INFO: dict[str, dict] = {}
for _module in DETECTOR_MODULES:
    RULE_INFO.update(getattr(_module, "RULE_INFO", {}))


def detect_all(events: Iterable[Event]) -> list[Finding]:
    materialized = list(events)
    findings: list[Finding] = []
    for module in DETECTOR_MODULES:
        findings.extend(module.detect(materialized))
    return findings
