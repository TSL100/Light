"""Run linuxdfir `run` in-process, timing phases and recording peak memory.

Measures wall-clock per phase (verify/parse/detect/report), total wall time
and the process peak working set (Windows: GetProcessMemoryInfo). Writes a
results JSON even when the run crashes, so an OOM baseline still reports
the peak reached before termination.

Usage:
  python bench/run_bench.py EVIDENCE --out DIR --results FILE [--label NAME]
"""

from __future__ import annotations

import argparse
import ctypes
import json
import platform
import sys
import time
from ctypes import wintypes
from datetime import UTC, datetime
from pathlib import Path


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def peak_working_set_bytes() -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    counters = PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(counters)
    handle = kernel32.GetCurrentProcess()
    if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        return 0
    return int(counters.PeakWorkingSetSize)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--label", default="bench")
    args = parser.parse_args()

    from linuxdfir import cli

    phase_times: dict[str, float] = {}
    for name in ("cmd_verify", "cmd_parse", "cmd_detect", "cmd_report"):
        original = getattr(cli, name)

        def make_wrapper(phase_name, func):
            def wrapper(phase_args):
                t0 = time.perf_counter()
                try:
                    return func(phase_args)
                finally:
                    phase_times[phase_name] = round(time.perf_counter() - t0, 2)

            return wrapper

        setattr(cli, name, make_wrapper(name, original))

    started_iso = datetime.now(UTC).isoformat()
    wall_start = time.perf_counter()
    exit_code = None
    error = None
    result: dict = {}
    try:
        exit_code = cli.main(["run", str(args.evidence), "-o", str(args.out)])
    except BaseException as exc:  # noqa: BLE001 - bench harness must survive anything
        error = f"{type(exc).__name__}: {exc}"
        exit_code = -1
    finally:
        wall_total = round(time.perf_counter() - wall_start, 2)
        events = None
        stats_path = args.out / "timeline_stats.json"
        if stats_path.is_file():
            try:
                events = json.loads(stats_path.read_text(encoding="utf-8")).get("total")
            except (OSError, json.JSONDecodeError):
                events = None
        findings = None
        findings_path = args.out / "findings.json"
        if findings_path.is_file():
            try:
                findings = len(json.loads(findings_path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                findings = None
        result = {
            "label": args.label,
            "evidence": str(args.evidence),
            "out": str(args.out),
            "started_utc": started_iso,
            "ended_utc": datetime.now(UTC).isoformat(),
            "wall_total_seconds": wall_total,
            "phases_seconds": phase_times,
            "peak_working_set_mb": round(peak_working_set_bytes() / (1024 * 1024), 1),
            "events": events,
            "findings": findings,
            "exit_code": exit_code,
            "error": error,
            "python": platform.python_version(),
            "platform": platform.platform(),
        }
        args.results.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return 0 if exit_code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
