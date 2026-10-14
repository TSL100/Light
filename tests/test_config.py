"""Tests for detection tuning config (TOML defaults + user overrides)."""

from __future__ import annotations

from linuxdfir.config import DEFAULT_CONFIG_PATH, load_config


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
