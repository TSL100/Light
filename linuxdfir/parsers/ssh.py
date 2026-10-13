"""SSH parser: sshd_config, authorized_keys and known_hosts.

authorized_keys entries carry a SHA256 fingerprint of the decoded key blob
(hex, like ssh-keygen without the base64 wrapper), the key type, comment
and any leading options. Invalid key material is still recorded (marked
invalid) rather than dropped.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Iterator

from ..ingest import Evidence
from ..schema import Event
from . import user_for_path

PARSER_NAME = "ssh"
CONSUMES = ["ssh"]

INTERESTING_SETTINGS = {
    "permitrootlogin",
    "passwordauthentication",
    "permitemptypasswords",
    "challengeresponseauthentication",
    "kbdinteractiveauthentication",
    "pubkeyauthentication",
    "authorizedkeysfile",
    "x11forwarding",
    "allowusers",
    "denyusers",
    "allowgroups",
    "denygroups",
    "permituserenvironment",
    "maxauthtries",
    "permitsystemlogin",
}

KEY_TYPE_RE = re.compile(
    r"\b(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp\d+|sk-ssh-ed25519\S*|sk-ecdsa-sha2-nistp\d+\S*)\b"
)


def _fingerprint(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob, validate=True)
    except Exception:
        return None
    return hashlib.sha256(raw).hexdigest()


def _split_key_line(text: str) -> tuple[str | None, str | None, str | None, str | None]:
    match = KEY_TYPE_RE.search(text)
    if not match:
        return None, None, None, None
    key_type = match.group(1)
    before = text[: match.start()].strip()
    after = text[match.end() :].strip()
    options = before or None
    if not after:
        return options, key_type, None, None
    blob, _, comment = after.partition(" ")
    comment = comment.strip() or None
    return options, key_type, blob, comment


def _base(evidence, member, display, lineno, line, event_type, user, message, tags, confidence=1.0) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=user,
        source_artifact="ssh",
        event_type=event_type,
        message=message,
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=tags,
        confidence=confidence,
        parser=PARSER_NAME,
    )


def _unparsed(evidence, member, display, lineno, line) -> Event:
    return _base(evidence, member, display, lineno, line, "unparsed", user_for_path(display),
                 line.strip()[:500], ["unparsed"], 0.1)


def _parse_sshd_config(evidence, member, display, stats) -> Iterator[Event]:
    in_match = False
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        lowered = text.lower()
        if lowered.startswith("match "):
            in_match = True
            continue
        key, _, value = text.partition(" ")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, display, lineno, line)
            continue
        if key.lower() not in INTERESTING_SETTINGS:
            continue
        tags = ["ssh", "sshd_config"]
        if in_match:
            tags.append("match-block")
        stats["events"] += 1
        yield _base(
            evidence, member, display, lineno, line, "sshd_setting", None,
            f"sshd: {key} {value}", tags,
        )


def _parse_authorized_keys(evidence, member, display, user, stats) -> Iterator[Event]:
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        options, key_type, blob, comment = _split_key_line(text)
        if key_type is None or not blob:
            stats["events"] += 1
            stats["unparsed"] += 1
            yield _unparsed(evidence, member, display, lineno, line)
            continue
        digest = _fingerprint(blob)
        tags = ["ssh", "authorized_keys"]
        if options:
            tags.append("key-options")
        if digest is None:
            message = f"ssh key INVALID {key_type} {comment or ''} [options: {options or 'none'}]".strip()
            confidence = 0.5
        else:
            message = f"ssh key {key_type} SHA256:{digest} {comment or ''} [options: {options or 'none'}]".strip()
            confidence = 1.0
        stats["events"] += 1
        yield _base(evidence, member, display, lineno, line, "ssh_key", user, message, tags, confidence)


def _parse_known_hosts(evidence, member, display, user, stats) -> Iterator[Event]:
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        parts = text.split()
        message = f"known host entry: {text[:200]}"
        tags = ["ssh", "known_hosts"]
        if text.startswith("|"):
            tags.append("hashed")
        elif len(parts) >= 3:
            message = f"known host {parts[0]} keytype {parts[1]}"
        stats["events"] += 1
        yield _base(evidence, member, display, lineno, line, "ssh_known_host", user, message, tags)


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    user = user_for_path(display)
    if display.endswith("sshd_config"):
        yield from _parse_sshd_config(evidence, member, display, stats)
    elif "authorized_keys" in display:
        yield from _parse_authorized_keys(evidence, member, display, user, stats)
    elif "known_hosts" in display:
        yield from _parse_known_hosts(evidence, member, display, user, stats)
    else:
        stats["unparsed"] += 1
        yield _unparsed(evidence, member, display, 0, "<unknown ssh artifact>")
