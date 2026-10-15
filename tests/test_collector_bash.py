"""Bash fallback collector is exercised end-to-end only where WSL exists.

The analyzer itself is Windows/Python-only, so the whole flow (collect, then
verify) runs inside WSL. Without WSL these tests are skipped rather than
failing on a developer box that has no bash.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_SH = REPO_ROOT / "collector" / "linux_collector.sh"


def _wsl_repo_root() -> str:
    """Map the Windows checkout path to its WSL mount point."""
    text = str(REPO_ROOT).replace("\\", "/")
    drive, _, rest = text.partition(":")
    return f"/mnt/{drive.lower()}/{rest.lstrip('/')}"


REPO_WSL = _wsl_repo_root()
VENV_PY = REPO_WSL + "/.wslvenv/bin/python"
TEST_SCRIPT = REPO_WSL + "/tests/_bash_collector_flow.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("wsl.exe") is None,
    reason="requires wsl.exe (bash collector is Linux-only)",
)


def _wsl(script: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["wsl.exe", "-e", "bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(REPO_ROOT),
    )


def test_wsl_python_available():
    proc = _wsl(f"{VENV_PY} --version && {VENV_PY} -m pytest --version")
    assert proc.returncode == 0, proc.stderr
    assert "Python 3." in proc.stdout


def test_bash_collector_verify_end_to_end(tmp_path: Path):
    """Collect with bash_collector.sh and verify the archive with the analyzer."""
    assert COLLECTOR_SH.is_file()
    flow = REPO_ROOT / "tests" / "_bash_collector_flow.sh"
    assert flow.is_file()
    proc = _wsl(f"bash {TEST_SCRIPT}", timeout=300)
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "integrity_ok: True" in proc.stdout
    assert "integrity        : OK" in proc.stdout
    assert "files ok/missing/skipped:" in proc.stdout


def test_bash_manifest_schema_and_counts():
    """The bash collector emits the manifest schema the analyzer validates."""
    dump = f"{REPO_WSL}/.wsl_bash_summary.json"
    proc = _wsl(
        f"rm -f {dump}; bash {REPO_WSL}/tests/_bash_collector_dump.sh {dump}; "
        f"test -s {dump}",
        timeout=300,
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    summary = json.loads(Path(dump.replace(REPO_WSL, str(REPO_ROOT))).read_text(encoding="utf-8"))
    assert summary["schema"] == "linuxdfir/collector-manifest/1"
    assert summary["collector_name"] == "linuxdfir-collector"
    assert summary["hash_algorithm"] == "sha256"
    assert summary["tag"] == "pytest"
    assert summary["integrity_ok"] is True
    ok = summary["files_ok"]
    assert "/etc/passwd" in ok
    assert "/etc/hosts" in ok
    assert summary["files_not_present"]
    assert summary["not_present_with_reason"] is True
    assert "manifest.json" in summary["members"]
    assert any(m.startswith("evidence/") for m in summary["members"])


def test_bash_collector_matches_python_on_same_root():
    """Bash and Python collectors agree on the ok/not_present split for a fixture."""
    dump = f"{REPO_WSL}/.wsl_bash_parity.json"
    proc = _wsl(
        f"rm -f {dump}; bash {REPO_WSL}/tests/_bash_collector_parity.sh {dump}; "
        f"test -s {dump}",
        timeout=300,
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    parity = json.loads(Path(dump.replace(REPO_WSL, str(REPO_ROOT))).read_text(encoding="utf-8"))
    assert parity["bash_ok"] == parity["py_ok"], (
        f"ok mismatch\nbash: {parity['bash_ok']}\npy:   {parity['py_ok']}"
    )
    assert parity["bash_not_present"] == parity["py_not_present"], (
        f"not_present mismatch\nbash: {parity['bash_not_present']}\npy:   {parity['py_not_present']}"
    )
    assert parity["ok_equal"] is True
    assert parity["np_equal"] is True
    assert "/etc/passwd" in parity["bash_ok"]


def test_bash_collector_reports_not_present_paths():
    """Every absent target is logged, never silently dropped."""
    proc = _wsl(
        "set -e; "
        f"cd {REPO_WSL}; "
        "W=.wsl_bash_np; rm -rf \"$W\"; mkdir -p \"$W/root/etc\" \"$W/out\"; "
        "printf 'root:x:0:0:root:/root:/bin/bash\\n' > \"$W/root/etc/passwd\"; "
        "bash collector/linux_collector.sh --root \"$W/root\" -o \"$W/out\" --skip-live >/dev/null; "
        "tar -xzOf \"$W/out/evidence.tar.gz\" collect.log 2>/dev/null | grep -c 'NOT PRESENT'"
    )
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}"
    count = int(proc.stdout.strip() or "0")
    assert count > 0, "collector logged no NOT PRESENT lines"
