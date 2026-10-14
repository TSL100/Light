"""Central secret redaction, applied at Event construction.

Every parser benefits automatically (shell history, process command
lines, web query strings, shadow states, audit argv, ...): message and
raw text pass through :func:`redact_secrets` in ``Event.__post_init__``,
so no downstream artifact (events.jsonl, timeline.db/csv, findings,
reports) can carry a secret.

Covered: modular-crypt hashes ($1$ $5$ $6$ $y$ $2a$/$2b$/$2y$),
``sshpass -p``, ``--password=``/``--passwd``, ``mysql -p<pw>``,
``curl -u user:pass``, Bearer/Basic tokens, user:password in URLs and
password/token query parameters.

Surrounding fields are preserved (``admin:<hash>:20000`` keeps the
account and aging fields); the secret is replaced by
``[REDACTED-<KIND>:<fp8>]`` where fp8 is the first 8 hex chars of the
secret's SHA256, so reuse of the same secret stays correlatable without
being reversible. Markers never re-trigger the patterns (idempotent).
"""

from __future__ import annotations

import hashlib
import re

CRYPT_RE = re.compile(r"\$((?:2[aby])|[156]|y)\$[^\s$:]+(?:\$[^\s$:]+)+")
CRYPT_KINDS = {
    "1": "MD5CRYPT",
    "2a": "BCRYPT",
    "2b": "BCRYPT",
    "2y": "BCRYPT",
    "5": "SHA256CRYPT",
    "6": "SHA512CRYPT",
    "y": "YESCRYPT",
}

SSHPASS_Q_RE = re.compile(r"(\bsshpass\b[^\n]*?\s-p(?!ort\b)\s*)([\"'])([^\"']+)(\2)")
SSHPASS_RE = re.compile(r"(\bsshpass\b[^\n]*?\s-p(?!ort\b)\s*)(\"[^\"\n]*\"|'[^'\n]*'|\S+)")
PASS_Q_RE = re.compile(r"(--passw(?:or)?d\s*=\s*|--passw(?:or)?d\s+)([\"'])([^\"']+)(\2)")
PASS_RE = re.compile(r"(--passw(?:or)?d\s*=\s*|--passw(?:or)?d\s+)(\S+)")
MYSQL_RE = re.compile(r"(\bmysql\b[^\n]*?\s-p)(\"[^\"\n]*\"|'[^'\n]*'|\S+)")
CURL_RE = re.compile(r"(\bcurl\b[^\n]*?(?:-u|--user)\s+)(?:([^:\s\"']+):)?(\"[^\"\n]*\"|'[^'\n]*'|\S+)")
BEARER_RE = re.compile(r"(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)")
BASIC_RE = re.compile(r"(Authorization:\s*Basic\s+)(\S+)")
URL_CREDS_RE = re.compile(r"((?:https?|ftp)://[^/\s:@?#]+:)([^/\s@?#]+)(@)")
QUERY_RE = re.compile(
    r"([?&](?P<key>password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth[_-]?token"
    r"|session[_-]?id|client[_-]?secret)=)([^&\s\"']+)"
)


def _fp(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _already_redacted(value: str) -> bool:
    return _strip_quotes(value).startswith("[REDACTED-")


def _mark(kind: str, secret: str) -> str:
    return f"[REDACTED-{kind}:{_fp(_strip_quotes(secret))}]"


def _crypt(match: re.Match) -> str:
    if _already_redacted(match.group(0)):
        return match.group(0)
    return _mark(CRYPT_KINDS[match.group(1)], match.group(0))


def _sshpass_q(match: re.Match) -> str:
    if _already_redacted(match.group(4)):
        return match.group(0)
    quote = match.group(3)
    return match.group(1) + quote + _mark("PASSWORD", match.group(4)) + quote


def _sshpass(match: re.Match) -> str:
    if _already_redacted(match.group(2)):
        return match.group(0)
    return match.group(1) + _mark("PASSWORD", match.group(2))


def _pass_q(match: re.Match) -> str:
    if _already_redacted(match.group(3)):
        return match.group(0)
    quote = match.group(2)
    return match.group(1) + quote + _mark("PASSWORD", match.group(3)) + quote


def _password(match: re.Match) -> str:
    if _already_redacted(match.group(2)):
        return match.group(0)
    return match.group(1) + _mark("PASSWORD", match.group(2))


def _curl(match: re.Match) -> str:
    if _already_redacted(match.group(3)):
        return match.group(0)
    prefix, user, secret = match.groups()
    marker = _mark("URL-CREDENTIAL", secret)
    return prefix + (user + ":" if user else "") + marker


def _token(match: re.Match) -> str:
    if _already_redacted(match.group(2)):
        return match.group(0)
    return match.group(1) + _mark("TOKEN", match.group(2))


def _url_creds(match: re.Match) -> str:
    if _already_redacted(match.group(2)):
        return match.group(0)
    return match.group(1) + _mark("URL-CREDENTIAL", match.group(2)) + match.group(3)


def _query(match: re.Match) -> str:
    if _already_redacted(match.group(3)):
        return match.group(0)
    key = match.group("key").lower()
    kind = "PASSWORD" if ("pass" in key or key == "pwd") else "TOKEN"
    return match.group(1) + _mark(kind, match.group(3))


def redact_secrets(text: str | None) -> str | None:
    """Replace secrets in free text with fingerprinted markers. None-safe.

    Every substitution is gated on a literal its pattern necessarily
    contains (``$`` for crypt hashes, ``--passw`` for password flags,
    ...): a gate miss is exactly the pattern's no-match case, so output
    is identical to an unconditional cascade but costs one substring
    scan instead of eleven regex scans per line.
    """
    if text is None or not isinstance(text, str):
        return text

    if "$" in text:
        text = CRYPT_RE.sub(_crypt, text)
    if "sshpass" in text:
        text = SSHPASS_Q_RE.sub(_sshpass_q, text)
        text = SSHPASS_RE.sub(_sshpass, text)
    if "--passw" in text:
        text = PASS_Q_RE.sub(_pass_q, text)
        text = PASS_RE.sub(_password, text)
    if "mysql" in text:
        text = MYSQL_RE.sub(_password, text)
    if "curl" in text:
        text = CURL_RE.sub(_curl, text)
    if "Bearer" in text:
        text = BEARER_RE.sub(_token, text)
    if "Authorization" in text:
        text = BASIC_RE.sub(_token, text)
    if "://" in text:
        text = URL_CREDS_RE.sub(_url_creds, text)
    if "?" in text or "&" in text:
        text = QUERY_RE.sub(_query, text)
    return text
