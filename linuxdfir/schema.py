"""Normalized Event / Finding schema plus the artifact registry.

Every parser emits Events; every detector emits Findings. Both serialize to
plain JSON dicts so the pipeline (JSONL events, JSON findings, CSV/HTML
reports) stays dependency-free.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from fnmatch import fnmatch

TIMESTAMP_QUALITIES = ("exact", "inferred_year", "tz_assumed", "none")


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(severity: Severity) -> int:
    return SEVERITY_RANK[severity]


def parse_severity(value: str | Severity) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).lower())
    except ValueError:
        raise ValueError(f"unknown severity: {value!r}") from None


def _dt_to_str(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValueError("naive datetime cannot be serialized; use timezone-aware UTC")
    return value.astimezone(UTC).isoformat()


def _dt_from_str(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


@dataclass
class Event:
    timestamp_utc: datetime | None
    host: str | None
    user: str | None
    source_artifact: str
    event_type: str
    message: str
    evidence_path: str
    line_or_offset: int | str | None = None
    raw: str = ""
    tags: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    confidence: float = 1.0
    parser: str = ""
    timestamp_quality: str = "exact"
    repeat_count: int = 1

    def __post_init__(self) -> None:
        if self.timestamp_utc is not None and self.timestamp_utc.tzinfo is None:
            raise ValueError("timestamp_utc must be timezone-aware or None")
        if self.timestamp_quality not in TIMESTAMP_QUALITIES:
            raise ValueError(f"unknown timestamp_quality: {self.timestamp_quality!r}")
        if self.timestamp_utc is None and self.timestamp_quality == "exact":
            self.timestamp_quality = "none"
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence out of range: {self.confidence!r}")
        if self.repeat_count < 1:
            raise ValueError(f"repeat_count must be >= 1: {self.repeat_count!r}")

    def to_dict(self) -> dict:
        return {
            "timestamp_utc": _dt_to_str(self.timestamp_utc),
            "timestamp_quality": self.timestamp_quality,
            "host": self.host,
            "user": self.user,
            "source_artifact": self.source_artifact,
            "event_type": self.event_type,
            "message": self.message,
            "evidence_path": self.evidence_path,
            "line_or_offset": self.line_or_offset,
            "raw": self.raw,
            "tags": list(self.tags),
            "mitre_ids": list(self.mitre_ids),
            "confidence": self.confidence,
            "parser": self.parser,
            "repeat_count": self.repeat_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Event:
        return cls(
            timestamp_utc=_dt_from_str(data.get("timestamp_utc")),
            timestamp_quality=data.get("timestamp_quality", "exact"),
            host=data.get("host"),
            user=data.get("user"),
            source_artifact=data["source_artifact"],
            event_type=data["event_type"],
            message=data.get("message", ""),
            evidence_path=data["evidence_path"],
            line_or_offset=data.get("line_or_offset"),
            raw=data.get("raw", ""),
            tags=list(data.get("tags", [])),
            mitre_ids=list(data.get("mitre_ids", [])),
            confidence=data.get("confidence", 1.0),
            parser=data.get("parser", ""),
            repeat_count=data.get("repeat_count", 1),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class Ref:
    evidence_path: str
    line_or_offset: int | str | None = None

    def to_dict(self) -> dict:
        return {"evidence_path": self.evidence_path, "line_or_offset": self.line_or_offset}

    @classmethod
    def from_dict(cls, data: dict) -> Ref:
        return cls(evidence_path=data["evidence_path"], line_or_offset=data.get("line_or_offset"))


def make_finding_id(rule: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join([rule, *[str(part) for part in parts]]).encode("utf-8")).hexdigest()
    return digest[:16]


@dataclass
class Finding:
    id: str
    rule: str
    severity: Severity
    title: str
    description: str
    mitre_ids: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    count: int = 1
    refs: list[Ref] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = parse_severity(self.severity)
        for name in ("first_seen", "last_seen"):
            value = getattr(self, name)
            if value is not None and value.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware or None")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule": self.rule,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "mitre_ids": list(self.mitre_ids),
            "first_seen": _dt_to_str(self.first_seen),
            "last_seen": _dt_to_str(self.last_seen),
            "count": self.count,
            "refs": [ref.to_dict() for ref in self.refs],
        }

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        return cls(
            id=data["id"],
            rule=data["rule"],
            severity=parse_severity(data["severity"]),
            title=data.get("title", ""),
            description=data.get("description", ""),
            mitre_ids=list(data.get("mitre_ids", [])),
            first_seen=_dt_from_str(data.get("first_seen")),
            last_seen=_dt_from_str(data.get("last_seen")),
            count=data.get("count", 1),
            refs=[Ref.from_dict(ref) for ref in data.get("refs", [])],
        )


@dataclass(frozen=True)
class ArtifactSpec:
    name: str
    patterns: tuple[str, ...]
    description: str = ""


ARTIFACTS: dict[str, ArtifactSpec] = {
    "auth_log": ArtifactSpec(
        "auth_log",
        ("/var/log/auth.log*", "/var/log/secure*"),
        "SSH / authentication log, including rotated and compressed parts",
    ),
    "wtmp": ArtifactSpec("wtmp", ("/var/log/wtmp",), "binary login records"),
    "btmp": ArtifactSpec("btmp", ("/var/log/btmp",), "binary failed-login records"),
    "lastlog": ArtifactSpec("lastlog", ("/var/log/lastlog",), "binary last-login table"),
    "bash_history": ArtifactSpec(
        "bash_history",
        ("/home/*/.bash_history", "/root/.bash_history", "/*/.bash_history"),
        "bash shell history per user",
    ),
    "zsh_history": ArtifactSpec(
        "zsh_history",
        ("/home/*/.zsh_history", "/root/.zsh_history"),
        "zsh shell history per user",
    ),
    "viminfo": ArtifactSpec(
        "viminfo",
        ("/home/*/.viminfo", "/root/.viminfo"),
        "vim history per user",
    ),
    "python_history": ArtifactSpec(
        "python_history",
        ("/home/*/.python_history", "/root/.python_history"),
        "python REPL history per user",
    ),
    "cron": ArtifactSpec(
        "cron",
        (
            "/etc/crontab",
            "/etc/anacrontab",
            "/etc/cron.d/*",
            "/etc/cron.hourly/*",
            "/etc/cron.daily/*",
            "/etc/cron.weekly/*",
            "/etc/cron.monthly/*",
            "/var/spool/cron/*",
            "/var/spool/cron/crontabs/*",
        ),
        "system and per-user cron jobs",
    ),
    "systemd_unit": ArtifactSpec(
        "systemd_unit",
        ("/etc/systemd/system/*", "/usr/lib/systemd/system/*"),
        "systemd unit files, including masked units",
    ),
    "passwd": ArtifactSpec("passwd", ("/etc/passwd",), "user accounts"),
    "shadow": ArtifactSpec("shadow", ("/etc/shadow",), "password hashes"),
    "group": ArtifactSpec("group", ("/etc/group",), "groups"),
    "sudoers": ArtifactSpec(
        "sudoers",
        ("/etc/sudoers", "/etc/sudoers.d/*"),
        "sudo policy",
    ),
    "ssh": ArtifactSpec(
        "ssh",
        ("/etc/ssh/sshd_config", "/*/.ssh/authorized_keys", "/*/.ssh/known_hosts"),
        "sshd config and per-user ssh trust files",
    ),
    "ld_preload": ArtifactSpec("ld_preload", ("/etc/ld.so.preload",), "global library preload"),
    "profile_scripts": ArtifactSpec(
        "profile_scripts",
        (
            "/etc/profile.d/*",
            "/home/*/.bashrc",
            "/root/.bashrc",
            "/home/*/.profile",
            "/root/.profile",
            "/home/*/.bash_profile",
            "/root/.bash_profile",
        ),
        "login shell startup scripts",
    ),
    "package_logs": ArtifactSpec(
        "package_logs",
        (
            "/var/log/dpkg.log*",
            "/var/log/apt/history.log*",
            "/var/log/apt/term.log*",
            "/var/log/yum.log*",
            "/var/log/yum/*",
            "/var/log/dnf*",
            "/var/log/dnf/*",
        ),
        "package manager history",
    ),
    "syslog": ArtifactSpec("syslog", ("/var/log/syslog*",), "system log"),
    "kern_log": ArtifactSpec("kern_log", ("/var/log/kern.log*",), "kernel log"),
    "auditd": ArtifactSpec("auditd", ("/var/log/audit/audit.log*",), "audit daemon log"),
    "web_logs": ArtifactSpec(
        "web_logs",
        (
            "/var/log/nginx/*access*log*",
            "/var/log/nginx/*error*log*",
            "/var/log/apache2/*access*log*",
            "/var/log/apache2/*error*log*",
            "/var/log/httpd/*access*log*",
            "/var/log/httpd/*error*log*",
        ),
        "web server access and error logs",
    ),
    "network_config": ArtifactSpec(
        "network_config",
        ("/etc/hosts", "/etc/resolv.conf", "/etc/ssh/sshd_config", "/etc/iptables/rules.v4", "/etc/iptables/rules.v6"),
        "static network configuration",
    ),
    "recent_files": ArtifactSpec("recent_files", ("triage/recent_files.txt",), "recently changed files listing"),
    "suid_sgid": ArtifactSpec("suid_sgid", ("triage/suid_sgid.txt",), "setuid/setgid files listing"),
    "hidden_files": ArtifactSpec("hidden_files", ("triage/hidden_files.txt",), "hidden files listing"),
    "tmp_listing": ArtifactSpec("tmp_listing", ("triage/tmp_listing.txt",), "/tmp listing"),
    "var_tmp_listing": ArtifactSpec("var_tmp_listing", ("triage/var_tmp_listing.txt",), "/var/tmp listing"),
    "dev_shm_listing": ArtifactSpec("dev_shm_listing", ("triage/dev_shm_listing.txt",), "/dev/shm listing"),
    "live_ps": ArtifactSpec("live_ps", ("live/ps_auxf.txt",), "process snapshot"),
    "live_ss": ArtifactSpec("live_ss", ("live/ss_tulpn.txt",), "socket snapshot"),
    "live_lsof": ArtifactSpec("live_lsof", ("live/lsof_nP.txt",), "open files snapshot"),
    "live_who": ArtifactSpec("live_who", ("live/who.txt",), "logged-in users snapshot"),
    "live_last": ArtifactSpec("live_last", ("live/last.txt",), "recent logins snapshot"),
    "live_lsmod": ArtifactSpec("live_lsmod", ("live/lsmod.txt",), "kernel modules snapshot"),
    "live_mount": ArtifactSpec("live_mount", ("live/mount.txt",), "mount table snapshot"),
    "live_df": ArtifactSpec("live_df", ("live/df.txt",), "disk usage snapshot"),
    "live_docker": ArtifactSpec("live_docker", ("live/docker_ps_a.txt",), "container snapshot"),
    "live_iptables": ArtifactSpec(
        "live_iptables", ("live/iptables_save.txt", "live/ip6tables_save.txt"), "firewall rules snapshot"
    ),
    "live_crontab": ArtifactSpec("live_crontab", ("live/crontab_*.txt",), "per-user crontab snapshot"),
    "live_journal": ArtifactSpec("live_journal", ("live/journalctl_export.txt",), "journal export"),
}


def match_artifact(name: str, *, original_path: str | None = None, archive_path: str | None = None) -> bool:
    spec = ARTIFACTS[name]
    candidates = [path for path in (original_path, archive_path) if path]
    return any(fnmatch(candidate, pattern) for candidate in candidates for pattern in spec.patterns)


def artifacts_for_path(*, original_path: str | None = None, archive_path: str | None = None) -> list[str]:
    return [
        name
        for name in ARTIFACTS
        if match_artifact(name, original_path=original_path, archive_path=archive_path)
    ]
