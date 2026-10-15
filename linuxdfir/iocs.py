"""IOC extraction: IPs, domains, URLs, hashes, paths, usernames.

Scans every event message/raw plus every finding title/description,
splits indicators into an external bucket and an internal one
(private/loopback/documentation IPs, local paths, usernames), and
defangs display values (hxxp, [@], [.]) so the offline report can show
clickable-looking indicators that stay inert.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from .schema import Event, Finding

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|su|onion|"
    r"test|local|internal|lan|dev|site|club|online|shop|live|co|me|cc|ws)\b",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
PATH_RE = re.compile(r"/[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)+")

USERNAME_PATTERNS = (
    re.compile(r"\bfor '([A-Za-z_][A-Za-z0-9_-]{0,31})'"),
    re.compile(r"\buser '([A-Za-z_][A-Za-z0-9_-]{0,31})'"),
    re.compile(r"\buser[= ]([A-Za-z_][A-Za-z0-9_-]{1,31})\b"),
    # Unquoted for/as captures reject hyphenated tokens (netcat-family etc.).
    re.compile(r"\bfor ([A-Za-z_][A-Za-z0-9]{1,31})(?![\w-])"),
    re.compile(r"\bas ([A-Za-z_][A-Za-z0-9]{1,31})(?![\w-])"),
)

_USER_STOPWORDS = frozenset(
    {
        "user", "users", "password", "publickey", "accepted", "failed",
        "invalid", "login", "logins", "session", "sessions", "account",
        "accounts", "sudo", "ssh", "tty", "pts", "port", "tcp", "udp",
        "http", "https", "unknown", "yes", "no", "all", "the", "a", "an",
        "from", "with", "and", "or", "not", "new", "uid", "gid", "this",
        "that",
    }
)

DEFAULT_MAX_PER_TYPE = 200


def is_internal_ip(value: str) -> bool:
    """Private, loopback, link-local, documentation or otherwise non-routable."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return True
    return value.startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def defang(value: str, kind: str) -> str:
    """Make an indicator inert for display: hxxp, [@], [.]."""
    if kind == "url":
        value = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
        return value.replace("@", "[@]").replace(".", "[.]")
    if kind in ("ip", "domain"):
        return value.replace(".", "[.]")
    return value


def extract_ips(text: str) -> list[str]:
    found: list[str] = []
    for match in IPV4_RE.findall(text):
        try:
            ipaddress.ip_address(match)
        except ValueError:
            continue
        if match not in found:
            found.append(match)
    return found


def extract_paths(text: str) -> list[str]:
    found: list[str] = []
    for match in PATH_RE.findall(text):
        if match not in found:
            found.append(match)
    return found


def extract_users(text: str) -> list[str]:
    found: list[str] = []
    for pattern in USERNAME_PATTERNS:
        for match in pattern.findall(text):
            user = match.strip()
            if not user or user.lower() in _USER_STOPWORDS:
                continue
            if user not in found:
                found.append(user)
    return found


def extract_iocs(
    events: Iterable[Event],
    findings: Iterable[Finding],
    config: dict | None = None,
) -> dict:
    """Return {"external": [...], "internal": [...]} sorted by (type, value)."""
    ioc_cfg = (config or {}).get("ioc", {})
    suppress = {str(item).lower() for item in ioc_cfg.get("suppress", [])}
    max_per_type = int(ioc_cfg.get("max_per_type", DEFAULT_MAX_PER_TYPE))

    collected: dict[tuple[str, str], dict] = {}

    def add(kind: str, value: str, source: str, internal: bool) -> None:
        lowered = value.lower()
        if lowered in suppress:
            return
        key = (kind, lowered)
        entry = collected.get(key)
        if entry is None:
            entry = {
                "type": kind,
                "value": value,
                "defanged": defang(value, kind),
                "internal": internal,
                # Sources accumulate in a set: a list membership test here is
                # O(sources) per add and goes quadratic on large evidence
                # (one popular IP can be referenced by tens of thousands of
                # events). Measured: >9 min on 1M events as a list, ~90s as a set.
                "_sources": set(),
            }
            collected[key] = entry
        entry["_sources"].add(source)

    def scan_text(text: str, source: str) -> None:
        if not text:
            return
        work = text
        for match in URL_RE.findall(work):
            add("url", match.rstrip(").,;\"'"), source, False)
        work = URL_RE.sub(" ", work)
        for match in extract_ips(work):
            add("ip", match, source, is_internal_ip(match))
        work = IPV4_RE.sub(" ", work)
        for match in DOMAIN_RE.findall(work):
            add("domain", match.lower(), source, False)
        for match in HASH_RE.findall(work):
            add("hash", match.lower(), source, False)
        for match in PATH_RE.findall(work):
            add("path", match, source, True)
        for match in extract_users(work):
            add("username", match, source, True)

    for event in events:
        ref = f"{event.evidence_path}:{event.line_or_offset}"
        scan_text(event.message, ref)
        if event.raw and event.raw != event.message:
            scan_text(event.raw, ref)
        if event.user:
            add("username", event.user, ref, True)

    for finding in findings:
        source = f"finding:{finding.id}"
        scan_text(f"{finding.title} {finding.description}", source)

    for entry in collected.values():
        entry["sources"] = sorted(entry.pop("_sources"))
    entries = sorted(collected.values(), key=lambda item: (item["type"], item["value"]))
    capped: dict[str, list[dict]] = {"external": [], "internal": []}
    per_type: dict[tuple[bool, str], int] = {}
    for entry in entries:
        bucket = "internal" if entry["internal"] else "external"
        count_key = (entry["internal"], entry["type"])
        seen = per_type.get(count_key, 0)
        if seen >= max_per_type:
            continue
        per_type[count_key] = seen + 1
        capped[bucket].append(entry)
    return capped
