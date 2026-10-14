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
