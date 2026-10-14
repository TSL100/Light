"""Tests for detection tuning config (TOML defaults + user overrides)."""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path

from linuxdfir.config import DEFAULT_CONFIG_PATH, load_config

REPO_ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = REPO_ROOT / "linuxdfir"


def test_shipped_defaults():
    assert DEFAULT_CONFIG_PATH.is_file()
    cfg = load_config(None)
    assert "nmap" in cfg["package_tools"]["tools"]
    assert "netcat" in cfg["package_tools"]["tools"]
    assert cfg["bulk_batch"]["threshold"] == 50
    assert cfg["bulk_batch"]["window_minutes"] == 10
    assert "netcat-openbsd" in cfg["default_image_packages"]["packages"]
    assert "netcat-traditional" not in cfg["default_image_packages"]["packages"]


def test_user_override_merges(tmp_path):
    custom = tmp_path / "custom.toml"
    custom.write_text(
        "[bulk_batch]\nthreshold = 5\n"
        "[default_image_packages]\npackages = [\"tcpdump\"]\n",
        encoding="utf-8",
    )
    cfg = load_config(custom)
    assert cfg["bulk_batch"]["threshold"] == 5
    assert cfg["bulk_batch"]["window_minutes"] == 10
    assert cfg["default_image_packages"]["packages"] == ["tcpdump"]
    assert "nmap" in cfg["package_tools"]["tools"]


def test_missing_file_raises(tmp_path):
    import pytest

    with pytest.raises(OSError):
        load_config(tmp_path / "does-not-exist.toml")


def test_pyproject_declares_package_data():
    with open(REPO_ROOT / "pyproject.toml", "rb") as handle:
        project = tomllib.load(handle)
    shipped = project["tool"]["setuptools"]["package-data"]["linuxdfir"]
    assert "detection.toml" in shipped


def test_config_loads_from_installed_package_path(tmp_path):
    site = tmp_path / "site-packages" / "linuxdfir"
    site.mkdir(parents=True)
    for name in ("__init__.py", "config.py", "detection.toml"):
        (site / name).write_bytes((PKG_DIR / name).read_bytes())
    spec = importlib.util.spec_from_file_location("installed_linuxdfir.config", site / "config.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.DEFAULT_CONFIG_PATH.parent == site
    cfg = module.load_config(None)
    assert cfg["bulk_batch"]["threshold"] == 50
    assert "netcat-openbsd" in cfg["default_image_packages"]["packages"]
