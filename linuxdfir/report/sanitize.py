"""Report-layer text safety: shadow-hash redaction and CSV formula neutralization."""

from __future__ import annotations

import re

SHADOW_HASH_RE = re.compile(r"\$[0-9a-z]+\$[^$\s:]+(?:\$[^$\s:]+)+")
REDACTED_MARKER = "[HASH-REDACTED]"
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def redact_shadow_hashes(text: str | None) -> str | None:
    """Replace modular-crypt password hashes (e.g. $6$salt$hash) with a marker."""
    if text is None:
        return None
    return SHADOW_HASH_RE.sub(REDACTED_MARKER, text)


def neutralize_formula(value):
    """Prefix spreadsheet-formula triggers so CSV cells stay inert."""
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def sanitize_cell(value):
    return neutralize_formula(redact_shadow_hashes(value))
