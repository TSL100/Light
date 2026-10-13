import gzip
import io
import json
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import flip_first_byte, make_mini_evidence, repack_variant

from linuxdfir import cli
from linuxdfir.ingest import Evidence, EvidenceError, UnsafeArchiveError, resolve_tzinfo
from linuxdfir.schema import Severity


def make_tar(path, entries):
    with tarfile.open(path, "w:gz") as tar:
        for info, data in entries:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def regular_member(name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def test_verify_passes_on_generated_hosts(generated):
    for profile in ("infected", "clean"):
        archive = generated["results"][profile]["archive"]
        with Evidence.open(archive) as evidence:
            report = evidence.verify()
        assert report["integrity_ok"] is True
        assert report["sidecar"]["status"] == "ok"
        assert report["mismatch"] == [] and report["missing"] == [] and report["extra"] == []
        assert report["counts"]["ok"] > 0
        assert evidence.integrity_findings == []
        assert evidence.context.hostname in ("web01", "web02")


def test_verify_works_on_extracted_folder(generated, tmp_path):
    archive = generated["results"]["infected"]["archive"]
    folder = tmp_path / "extracted"
    folder.mkdir()
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(folder, filter="data")
    with Evidence.open(folder) as evidence:
        assert evidence.kind == "folder"
        report = evidence.verify()
    assert report["integrity_ok"] is True
    assert report["sidecar"]["status"] == "not_applicable"
    assert report["counts"]["metadata_only"] >= 1


def test_masked_units_are_metadata_only_not_mismatches(generated):
    archive = generated["results"]["infected"]["archive"]
    with Evidence.open(archive) as evidence:
        report = evidence.verify()
    assert "/etc/systemd/system/auditd.service" in report["metadata_only"]
    assert evidence.integrity_findings == []


def test_hash_mismatch_detected(generated, tmp_path):
    src = generated["results"]["infected"]["archive"]
    with tarfile.open(src, "r:gz") as tar:
        original = tar.extractfile("evidence/var/log/auth.log").read()
    dst = repack_variant(
        src, tmp_path / "tampered.tar.gz", modify={"evidence/var/log/auth.log": flip_first_byte(original)}
    )
    with Evidence.open(dst) as evidence:
        report = evidence.verify()
    assert report["integrity_ok"] is False
    assert report["mismatch"] == ["evidence/var/log/auth.log"]
    assert len(evidence.integrity_findings) == 1
    finding = evidence.integrity_findings[0]
    assert finding.rule == "evidence_integrity"
    assert finding.severity is Severity.HIGH
    assert "evidence/var/log/auth.log" in finding.title


def test_missing_member_detected(generated, tmp_path):
    src = generated["results"]["infected"]["archive"]
    dst = repack_variant(src, tmp_path / "dropped.tar.gz", drop=["evidence/etc/passwd"])
    with Evidence.open(dst) as evidence:
        report = evidence.verify()
    assert report["integrity_ok"] is False
    assert report["missing"] == ["evidence/etc/passwd"]
    assert evidence.integrity_findings[0].severity is Severity.HIGH


def test_extra_member_detected(generated, tmp_path):
    src = generated["results"]["clean"]["archive"]
    dst = repack_variant(src, tmp_path / "extra.tar.gz", add={"evidence/evil.txt": b"planted\n"})
    with Evidence.open(dst) as evidence:
        report = evidence.verify()
    assert report["integrity_ok"] is False
    assert report["extra"] == ["evidence/evil.txt"]
    assert evidence.integrity_findings[0].severity is Severity.HIGH


def test_sidecar_mismatch_is_high(generated, tmp_path):
    src = generated["results"]["clean"]["archive"]
    dst = repack_variant(src, tmp_path / "badsidecar.tar.gz", sidecar="wrong")
    with Evidence.open(dst) as evidence:
        report = evidence.verify()
    assert report["integrity_ok"] is False
    assert report["sidecar"]["status"] == "mismatch"
    assert any(f.severity is Severity.HIGH and "sidecar" in f.title.lower() for f in evidence.integrity_findings)


def test_sidecar_missing_is_medium(generated, tmp_path):
    src = generated["results"]["clean"]["archive"]
    dst = repack_variant(src, tmp_path / "nosidecar.tar.gz", sidecar="missing")
    with Evidence.open(dst) as evidence:
        report = evidence.verify()
    assert report["integrity_ok"] is False
    assert report["sidecar"]["status"] == "missing"
    assert any(f.severity is Severity.MEDIUM for f in evidence.integrity_findings)


def mini_manifest_bytes():
    return json.dumps(
        {
            "schema": "linuxdfir/collector-manifest/1",
            "hostname": "mini",
            "collection_time_utc": "2026-01-03T06:00:00Z",
            "timezone": {"name": None, "utc_offset_seconds": None},
            "files": [],
            "live_commands": [],
            "triage": [],
        }
    ).encode()


@pytest.mark.parametrize(
    "name,target",
    [
        ("../evil.txt", None),
        ("/tmp/evil.txt", None),
        ("link", "/etc/passwd"),
        ("sub/../../evil.txt", None),
    ],
)
def test_unsafe_members_rejected(tmp_path, name, target):
    path = tmp_path / "evil.tar.gz"
    manifest_info, manifest_data = regular_member("manifest.json", mini_manifest_bytes())
    if target is None:
        bad_info, bad_data = regular_member(name, b"evil\n")
    else:
        bad_info = tarfile.TarInfo(name)
        bad_info.type = tarfile.SYMTYPE
        bad_info.linkname = target
        bad_data = None
    make_tar(path, [(manifest_info, manifest_data), (bad_info, bad_data)])
    with pytest.raises(UnsafeArchiveError):
        Evidence.open(path)


def test_internal_symlink_accepted_but_unreadable(tmp_path):
    path = tmp_path / "link.tar.gz"
    manifest_info, manifest_data = regular_member("manifest.json", mini_manifest_bytes())
    host_info, host_data = regular_member("evidence/etc/hostname", b"mini\n")
    link_info = tarfile.TarInfo("alias")
    link_info.type = tarfile.SYMTYPE
    link_info.linkname = "evidence/etc/hostname"
    make_tar(path, [(manifest_info, manifest_data), (host_info, host_data), (link_info, None)])
    with Evidence.open(path) as evidence:
        assert "alias" not in evidence.members
        with pytest.raises(EvidenceError):
            evidence.read_bytes("alias")


def test_timezone_resolves_iana_cairo(generated):
    archive = generated["results"]["infected"]["archive"]
    with Evidence.open(archive) as evidence:
        assert evidence.tz_source == "iana"
        assert evidence.tzinfo.key == "Africa/Cairo"
        local = datetime(2026, 1, 2, 3, 12, 44, tzinfo=evidence.tzinfo)
        assert local.utcoffset() == timedelta(seconds=7200)
        assert evidence.context.collection_time_utc == datetime(2026, 1, 3, 6, 0, tzinfo=UTC)


def test_timezone_fallback_to_fixed_offset(tmp_path):
    make_mini_evidence(tmp_path / "mini", tz_name="Mars/Olympus", tz_offset=7200)
    with Evidence.open(tmp_path / "mini") as evidence:
        assert evidence.tz_source == "fixed_offset"
        assert datetime(2026, 1, 2, tzinfo=evidence.tzinfo).utcoffset() == timedelta(seconds=7200)


def test_timezone_fallback_to_utc(tmp_path):
    make_mini_evidence(tmp_path / "mini", tz_name=None, tz_offset=None)
    with Evidence.open(tmp_path / "mini") as evidence:
        assert evidence.tz_source == "utc"


def test_resolve_tzinfo_unit():
    tz, source = resolve_tzinfo("Africa/Cairo", 7200)
    assert source == "iana"
    tz, source = resolve_tzinfo("Nope/Nowhere", -18000)
    assert source == "fixed_offset"
    assert datetime(2026, 6, 1, tzinfo=tz).utcoffset() == timedelta(seconds=-18000)
    tz, source = resolve_tzinfo(None, None)
    assert source == "utc"


def test_iter_lines_handles_gzip_transparently(tmp_path):
    payload = gzip.compress(b"line one\nline two\n")
    make_mini_evidence(tmp_path / "mini", files={"/var/log/auth.log.2.gz": payload})
    with Evidence.open(tmp_path / "mini") as evidence:
        assert list(evidence.iter_lines("evidence/var/log/auth.log.2.gz")) == [(1, "line one"), (2, "line two")]


def test_display_path_and_record_lookup(generated):
    archive = generated["results"]["infected"]["archive"]
    with Evidence.open(archive) as evidence:
        assert evidence.display_path("evidence/var/log/auth.log") == "/var/log/auth.log"
        assert evidence.display_path("live/ps_auxf.txt") == "live/ps_auxf.txt"
        rec = evidence.record_for_member("evidence/var/log/auth.log")
        assert rec["original_path"] == "/var/log/auth.log"
        assert evidence.record_for_member("live/ps_auxf.txt")["name"] == "ps_auxf"
        assert evidence.record_for_member("collect.log")["sha256"]
        assert evidence.record_for_member("nope") is None


def test_cli_verify_clean_and_tampered(generated, tmp_path, capsys):
    archive = generated["results"]["clean"]["archive"]
    assert cli.main(["verify", str(archive)]) == 0
    out = capsys.readouterr().out
    assert "integrity        : OK" in out
    with tarfile.open(archive, "r:gz") as tar:
        original = tar.extractfile("evidence/etc/hosts").read()
    dst = repack_variant(
        archive, tmp_path / "tampered.tar.gz", modify={"evidence/etc/hosts": flip_first_byte(original)}
    )
    assert cli.main(["verify", str(dst)]) == 2
    assert "FAILED" in capsys.readouterr().out


def test_cli_verify_writes_report(generated, tmp_path):
    archive = generated["results"]["clean"]["archive"]
    report_dir = tmp_path / "report"
    assert cli.main(["verify", str(archive), "--report-dir", str(report_dir)]) == 0
    report = json.loads((report_dir / "verify_report.json").read_text(encoding="utf-8"))
    assert report["integrity_ok"] is True
    assert report["counts"]["mismatch"] == 0


def test_cli_verify_missing_input():
    assert cli.main(["verify", str(Path("does-not-exist.tar.gz"))]) == 2
