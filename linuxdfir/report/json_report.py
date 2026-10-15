"""findings.json writer (shadow-hash redacted, atomic + verified)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..schema import Finding
from .sanitize import redact_shadow_hashes

# Headroom required on the destination volume before writing large outputs.
_FREE_SPACE_HEADROOM = 64 * 1024 * 1024


class WriteError(OSError):
    """Raised when an output file cannot be written or verified."""


def require_free_space(directory: str | Path, needed: int = _FREE_SPACE_HEADROOM) -> None:
    """Raise WriteError if the volume holding *directory* is nearly full."""
    target = Path(directory)
    probe = target if target.is_dir() else target.parent
    try:
        free = os.statvfs(probe)
        available = free.f_bavail * free.f_frsize
    except (OSError, AttributeError):
        # statvfs is unavailable on some platforms (e.g. Windows); skip the check.
        return
    if available < needed:
        raise WriteError(
            f"insufficient free space in {probe}: "
            f"{available} bytes available, {needed} bytes required"
        )


def atomic_write_text(path: str | Path, text: str, *, verify_json: bool = False) -> Path:
    """Write *text* to *path* atomically (temp file + fsync + os.replace).

    If *verify_json* is set the payload is re-parsed before the rename so a
    corrupt write is never promoted to the final filename.
    """
    target = Path(path)
    if verify_json:
        try:
            json.loads(text)
        except ValueError as exc:
            raise WriteError(f"refusing to write unparseable JSON to {target}: {exc}") from exc
    tmp = target.with_name(target.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise WriteError(f"failed to write {target}: {exc}") from exc
    return target


def atomic_write_json(path: str | Path, payload: object, *, indent: int = 2) -> Path:
    text = json.dumps(payload, indent=indent) + "\n"
    return atomic_write_text(path, text, verify_json=True)


def finding_to_redacted_dict(finding: Finding) -> dict:
    data = finding.to_dict()
    for key in ("title", "description"):
        data[key] = redact_shadow_hashes(data[key])
    return data


def write_findings(findings: list[Finding], path: str | Path) -> Path:
    payload = [finding_to_redacted_dict(finding) for finding in findings]
    return atomic_write_json(path, payload)
