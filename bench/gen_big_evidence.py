"""Generate a large synthetic LinuxDFIR evidence folder for performance benchmarks.

Deterministic given --seed: identical arguments produce byte-identical files.
Emits manifest.json plus these event sources (formats match the shipped
parsers auth_log / web_logs / syslog_kern):

  var/log/auth.log          ssh/sudo/session/cron mix, one bounded brute burst
  var/log/nginx/access.log  combined-format access lines, benign URIs
  var/log/syslog            cron/logind/systemd/kernel/generic mix
  var/log/kern.log          kernel-prefixed lines

Usage:
  python bench/gen_big_evidence.py --out DIR [--auth N --web N --syslog N --kern N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
HOST = "bench01"
TZ_NAME = "Africa/Cairo"
TZ_OFFSET_SECONDS = 7200
COLLECTION_TIME_UTC = "2026-01-16T12:00:00+00:00"
EVENT_START = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
EVENT_SPAN_SECONDS = 14 * 86400

USERS = ("alice", "bob", "carol", "dave", "svc_backup", "www-data", "deploy")
INVALID_USERS = tuple(f"u{i:03d}" for i in range(150)) + USERS
FAIL_IPS = tuple(f"203.0.113.{i}" for i in range(10, 40))
LAN_IPS = tuple(f"10.0.0.{i}" for i in range(2, 40))
BURST_IP = "203.0.113.66"
WEB_PATHS = ("/index.html", "/api/v1/status", "/static/app.js", "/login", "/healthz", "/images/logo.png")
WEB_UAS = ("Mozilla/5.0 (X11; Linux x86_64) bench", "curl/8.5.0", "python-requests/2.31.0")
KERN_MSGS = (
    "EXT4-fs (sda1): re-mounted. Quota mode: disabled.",
    "tcp_listen_port_range: setting range to 32768-60999",
    'audit: type=1400 apparmor="STATUS" operation="profile_load" profile="unconfined"',
    "mce: CPU 0: Package temperature above threshold",
)


def _pfx(dt_utc: datetime) -> str:
    local = dt_utc + timedelta(seconds=TZ_OFFSET_SECONDS)
    return f"{MONTHS[local.month - 1]} {local.day:2d} {local.hour:02d}:{local.minute:02d}:{local.second:02d}"


def _stamp_for(i: int, n: int) -> datetime:
    return EVENT_START + timedelta(seconds=(i * EVENT_SPAN_SECONDS) // max(n, 1))


def auth_line(i: int, n: int) -> str:
    dt = _stamp_for(i, n)
    pfx = _pfx(dt)
    pid = 40000 + (i % 25000)
    port = 20000 + (i % 40000)
    user = USERS[i % len(USERS)]
    burst_start = n // 2
    if burst_start <= i < burst_start + 40:
        return f"{pfx} {HOST} sshd[{pid}]: Failed password for root from {BURST_IP} port {port} ssh2"
    if i % 400_000 == 123_456:
        return f"Jan  5 03:17:22 {HOST} sshd[{pid}]: Accepted password for alice from 10.0.0.7 port {port} ssh2"
    kind = i % 100
    if kind < 3:
        iuser = INVALID_USERS[i % len(INVALID_USERS)]
        return (
            f"{pfx} {HOST} sshd[{pid}]: Failed password for invalid user {iuser} "
            f"from {FAIL_IPS[i % len(FAIL_IPS)]} port {port} ssh2"
        )
    if kind < 5:
        return (
            f"{pfx} {HOST} sshd[{pid}]: Failed password for root "
            f"from {FAIL_IPS[(i + 7) % len(FAIL_IPS)]} port {port} ssh2"
        )
    if kind < 7:
        return (
            f"{pfx} {HOST} sshd[{pid}]: Accepted password for {user} "
            f"from {LAN_IPS[i % len(LAN_IPS)]} port {port} ssh2"
        )
    if kind < 8:
        return (
            f"{pfx} {HOST} sshd[{pid}]: Accepted publickey for {user} "
            f"from {LAN_IPS[(i + 3) % len(LAN_IPS)]} port {port} ssh2: ED25519 SHA256:benchkey"
        )
    if kind < 11:
        opened = "opened" if kind % 2 else "closed"
        return f"{pfx} {HOST} sshd[{pid}]: pam_unix(sshd:session): session {opened} for user {user} by (uid=0)"
    if kind < 16:
        cmd = ("/usr/bin/systemctl status nginx", "/usr/bin/df -h", "/bin/cat /var/log/nginx/access.log")[i % 3]
        return f"{pfx} {HOST} sudo:     {user} : TTY=pts/{i % 4} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
    if kind < 18:
        return (
            f"{pfx} {HOST} su[4200]: pam_unix(su:session): session opened "
            f"for user root by {user}(uid={1000 + (i % 8)})"
        )
    if kind < 23:
        if kind % 2:
            return f"{pfx} {HOST} CRON[{pid}]: pam_unix(cron:session): session opened for user root by (uid=0)"
        return f"{pfx} {HOST} CRON[{pid}]: (root) CMD (/usr/local/bin/backup.sh)"
    if kind < 25:
        return f"{pfx} {HOST} sshd[{pid}]: Connection closed by {FAIL_IPS[i % len(FAIL_IPS)]} port {port} [preauth]"
    if kind < 27:
        return (
            f"{pfx} {HOST} sshd[{pid}]: Invalid user {INVALID_USERS[i % len(INVALID_USERS)]} "
            f"from {FAIL_IPS[(i + 5) % len(FAIL_IPS)]} port {port}"
        )
    if kind < 30:
        return f"{pfx} {HOST} systemd-logind[800]: New session {i % 9999} of user {user}."
    if kind < 32:
        ip = LAN_IPS[i % len(LAN_IPS)]
        return (
            f"{pfx} {HOST} sshd[{pid}]: pam_unix(sshd:auth): authentication failure; "
            f"logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={user}"
        )
    return f"{pfx} {HOST} systemd-logind[800]: Removed session {i % 9999}."


def web_line(i: int, n: int) -> str:
    dt = _stamp_for(i, n)
    ip = LAN_IPS[i % len(LAN_IPS)] if i % 20 else f"203.0.113.{(i % 50) + 10}"
    stamp = f"{dt.day:02d}/{MONTHS[dt.month - 1]}/{dt.year}:{dt:%H:%M:%S} +0000"
    path = WEB_PATHS[i % len(WEB_PATHS)]
    bucket = i % 100
    status = 200 if bucket < 92 else (304 if bucket < 96 else (404 if bucket < 99 else 500))
    size = 200 + (i % 4000)
    ua = WEB_UAS[i % len(WEB_UAS)]
    return f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def syslog_line(i: int, n: int) -> str:
    dt = _stamp_for(i, n)
    pfx = _pfx(dt)
    pid = 600 + (i % 900)
    user = USERS[i % len(USERS)]
    kind = i % 100
    if kind < 20:
        return f"{pfx} {HOST} CRON[{pid}]: (root) CMD (/usr/local/bin/backup.sh)"
    if kind < 32:
        return f"{pfx} {HOST} systemd-logind[{pid}]: New session {i % 9999} of user {user}."
    if kind < 45:
        return f"{pfx} {HOST} systemd[1]: Started Session {i % 9999} of user {user}."
    if kind < 52:
        return (
            f"{pfx} {HOST} kernel: [{(i % 100000) / 1000:.6f}] EXT4-fs (sda1): "
            f"mounted filesystem with ordered mode. Quota mode: none."
        )
    if kind < 56:
        return (
            f"{pfx} {HOST} sshd[{pid}]: Disconnected from user {user} "
            f"10.0.0.{(i % 30) + 2} port {20000 + (i % 40000)}"
        )
    return f"{pfx} {HOST} myapp[{pid}]: heartbeat ok seq={i}"


def kern_line(i: int, n: int) -> str:
    dt = _stamp_for(i, n)
    return f"{_pfx(dt)} {HOST} kernel: [{(i % 1000000) / 1000:.6f}] {KERN_MSGS[i % len(KERN_MSGS)]}"


def write_log(path: Path, count: int, line_fn) -> dict:
    digest = hashlib.sha256()
    written = 0
    buf: list[str] = []
    with open(path, "wb") as out:
        for i in range(count):
            buf.append(line_fn(i, count))
            if len(buf) >= 20000:
                data = ("\n".join(buf) + "\n").encode("utf-8")
                out.write(data)
                digest.update(data)
                written += len(data)
                buf.clear()
            if i and i % 1_000_000 == 0:
                print(f"    {path.name}: {i:,}/{count:,} lines", file=sys.stderr, flush=True)
        if buf:
            data = ("\n".join(buf) + "\n").encode("utf-8")
            out.write(data)
            digest.update(data)
            written += len(data)
    return {"sha256": digest.hexdigest(), "bytes": written}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--auth", type=int, default=5_000_000)
    parser.add_argument("--web", type=int, default=1_000_000)
    parser.add_argument("--syslog", type=int, default=6_000_000)
    parser.add_argument("--kern", type=int, default=1_000_000)
    args = parser.parse_args()

    started = time.perf_counter()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    specs = [
        ("var/log/auth.log", "/var/log/auth.log", args.auth, auth_line),
        ("var/log/nginx/access.log", "/var/log/nginx/access.log", args.web, web_line),
        ("var/log/syslog", "/var/log/syslog", args.syslog, syslog_line),
        ("var/log/kern.log", "/var/log/kern.log", args.kern, kern_line),
    ]
    files: list[dict] = []
    total_bytes = 0
    total_lines = 0
    for archive, original, count, line_fn in specs:
        path = out / archive
        path.parent.mkdir(parents=True, exist_ok=True)
        print(f"  writing {archive} ({count:,} lines)", file=sys.stderr, flush=True)
        info = write_log(path, count, line_fn)
        total_bytes += info["bytes"]
        total_lines += count
        files.append(
            {
                "original_path": original,
                "archive_path": archive,
                "sha256": info["sha256"],
                "size_bytes": info["bytes"],
                "status": "ok",
            }
        )
    manifest = {
        "schema": "linuxdfir.collector/1",
        "hostname": HOST,
        "collection_time_utc": COLLECTION_TIME_UTC,
        "timezone": {"name": TZ_NAME, "utc_offset_seconds": TZ_OFFSET_SECONDS},
        "environment": {"platform": "linux", "generator": "bench/gen_big_evidence.py"},
        "files": files,
        "counts": {"files_total": len(files), "files_ok": len(files)},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    summary = {
        "out": str(out),
        "total_bytes": total_bytes,
        "total_lines": total_lines,
        "seconds": round(time.perf_counter() - started, 1),
        "per_file": {rec["archive_path"]: rec["size_bytes"] for rec in files},
    }
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
