"""Detection tuning config (TOML).

`detection.toml` next to this module carries the sane defaults (tool
lists, bulk-batch thresholds, default-image allowlist). Pass a custom
file via `detect --config` / `run --config`; it is deep-merged over the
defaults so users tune without code changes.
"""

from __future__ import annotations

import copy
import tomllib
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).with_name("detection.toml")

FALLBACK_DEFAULTS: dict = {
    "package_tools": {
        "tools": ["nmap", "netcat", "hydra", "john", "masscan", "tcpdump", "socat"],
    },
    "bulk_batch": {"threshold": 50, "window_minutes": 10},
    "default_image_packages": {"packages": ["netcat-openbsd"]},
    "timestomp": {"threshold_days": 1},
    "suid": {
        "allowlist": [
            "/usr/bin/sudo", "/usr/bin/su", "/bin/su",
            "/usr/bin/passwd", "/bin/passwd",
            "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd",
            "/usr/bin/pkexec",
            "/usr/bin/mount", "/bin/mount", "/usr/bin/umount", "/bin/umount",
            "/usr/bin/fusermount", "/usr/bin/fusermount3",
            "/usr/bin/ntfs-3g",
            "/usr/bin/at", "/usr/bin/crontab",
            "/usr/bin/ssh-agent", "/usr/bin/ssh-keysign",
            "/usr/bin/ping", "/bin/ping", "/usr/bin/traceroute",
            "/usr/sbin/pppd",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
            "/usr/libexec/dbus-daemon-launch-helper",
            "/usr/lib/openssh/ssh-keysign",
        ],
        "writable_paths": ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/"],
    },
    "scratch_exec": {
        "paths": ["/tmp/", "/var/tmp/", "/dev/shm/"],
        "allowlist": [".placeholder"],
    },
    "recent_changes": {
        "paths": [
            "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
            "/etc/cron.weekly/", "/etc/cron.monthly/",
            "/etc/sudoers.d/", "/etc/ld.so.preload",
            "/etc/systemd/system/", "/etc/profile.d/",
        ],
        "allowlist_names": ["apt-compat", "logrotate", ".placeholder", "hardening.sh", "man-db.cron"],
    },
    "processes": {
        "allowed_ports": [22, 80, 443, 53, 25, 110, 143, 993, 995, 3306, 5432, 6379, 11211],
        "miner_patterns": ["xmrig", "stratum+tcp", "stratum+ssl", "minerd", "cpuminer", "srigger"],
        "reverse_shell_patterns": [
            "nc -e ", "ncat -e ", "socat EXEC", "socat exec",
            ">&/dev/tcp", "> /dev/tcp", "bash -i ", "sh -i ",
        ],
    },
    "containers": {
        "allowlist_images": [
            "nginx", "httpd", "redis", "memcached",
            "postgres", "mysql", "mariadb", "mongo",
            "alpine", "ubuntu", "debian", "busybox",
        ],
    },
}


def _load_toml(path: Path) -> dict:
    with open(path, "rb") as handle:
        data = tomllib.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"config is not a TOML table: {path}")
    return data


def _deep_merge(base: dict, override: dict) -> dict:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path: str | Path | None = None) -> dict:
    """Load detection config: shipped defaults optionally overridden by a user file."""
    if DEFAULT_CONFIG_PATH.is_file():
        config = _load_toml(DEFAULT_CONFIG_PATH)
    else:
        config = copy.deepcopy(FALLBACK_DEFAULTS)
    if path is not None:
        custom = _load_toml(Path(path))
        config = _deep_merge(config, custom)
    return config
