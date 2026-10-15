"""Multi-host cases: per-host runs, IOC overlap, combined timeline."""

from __future__ import annotations

import csv
import json

from conftest import make_mini_evidence

from linuxdfir import cli
from linuxdfir.case import (
    compute_overlap,
    evidence_fallback_name,
    sanitize_host_dir,
    unique_host_dir,
)

SHARED_IP = "91.203.67.42"
OTHER_IP = "45.148.10.88"


def _auth_line(time, ip=SHARED_IP):
    return (
        f"Oct 12 {time} web01 sshd[2101]: Failed password for root "
        f"from {ip} port 51299 ssh2\n"
    ).encode()


def _mini(root, hostname, files):
    root = make_mini_evidence(root, files=files)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["hostname"] = hostname
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return root


def _hosts(base):
    host_a = _mini(
        base / "ev-a",
        "web01",
        {"/var/log/auth.log": _auth_line("03:10:22")},
    )
    host_b = _mini(
        base / "ev-b",
        "web02",
        {"/var/log/auth.log": _auth_line("05:10:22")},
    )
    return host_a, host_b


def _case_json(case_dir):
    return json.loads((case_dir / "case.json").read_text(encoding="utf-8"))


def test_case_two_hosts_overlap_and_timeline(tmp_path):
    host_a, host_b = _hosts(tmp_path)
    case_dir = tmp_path / "case"
    assert cli.main(["case", str(host_a), str(host_b), "-o", str(case_dir)]) == 0
    assert (case_dir / "hosts" / "web01" / "findings.json").is_file()
    assert (case_dir / "hosts" / "web02" / "findings.json").is_file()
    assert (case_dir / "hosts" / "web01" / "report.html").is_file()
    record = _case_json(case_dir)
    assert record["schema"] == "linuxdfir/case/1"
    assert record["host_count"] == 2
    assert [h["outdir"] for h in record["hosts"]] == ["web01", "web02"]
    assert all(h["risk_score"] is not None for h in record["hosts"])
    assert all(h["integrity_ok"] for h in record["hosts"])
    ips = [e for e in record["overlap"] if e["type"] == "ip" and e["value"] == SHARED_IP]
    assert len(ips) == 1
    assert ips[0]["hosts"] == ["web01", "web02"]
    assert ips[0]["host_count"] == 2
    assert set(ips[0]["per_host"]) == {"web01", "web02"}
    assert (case_dir / "combined_timeline.csv").is_file()
    assert (case_dir / "combined_timeline.db").is_file()
    assert (case_dir / "combined_events.jsonl").is_file()
    with open(case_dir / "combined_timeline.csv", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows, "combined timeline must hold rows from both hosts"
    assert {row["host"] for row in rows} == {"web01", "web02"}
    stamps = [row["timestamp_utc"] for row in rows if row["timestamp_utc"]]
    assert stamps == sorted(stamps)
    assert record["timeline"]["rows"] == len(rows)


def test_case_same_hostname_dedup(tmp_path):
    host_a = make_mini_evidence(
        tmp_path / "ev-a", files={"/var/log/auth.log": _auth_line("03:10:22")}
    )
    host_b = make_mini_evidence(
        tmp_path / "ev-b", files={"/var/log/auth.log": _auth_line("04:10:22")}
    )
    case_dir = tmp_path / "case"
    assert cli.main(["case", str(host_a), str(host_b), "-o", str(case_dir)]) == 0
    assert (case_dir / "hosts" / "mini").is_dir()
    assert (case_dir / "hosts" / "mini_2").is_dir()
    record = _case_json(case_dir)
    assert [h["outdir"] for h in record["hosts"]] == ["mini", "mini_2"]


def test_case_no_overlap_still_builds_timeline(tmp_path):
    host_a = _mini(
        tmp_path / "ev-a", "web01",
        {"/var/log/auth.log": _auth_line("03:10:22", ip=SHARED_IP)},
    )
    host_b = _mini(
        tmp_path / "ev-b", "web02",
        {"/var/log/auth.log": _auth_line("05:10:22", ip=OTHER_IP)},
    )
    case_dir = tmp_path / "case"
    assert cli.main(["case", str(host_a), str(host_b), "-o", str(case_dir)]) == 0
    record = _case_json(case_dir)
    assert record["overlap"] == []
    assert record["overlap_stats"]["overlapping"] == 0
    assert record["timeline"]["rows"] >= 2


def test_case_internal_iocs_never_overlap(tmp_path):
    shared_path = b"Oct 12 03:10:22 web01 CRON[1]: (root) CMD (/usr/bin/backup)\n"
    host_a = _mini(tmp_path / "ev-a", "web01", {"/var/log/syslog": shared_path})
    host_b = _mini(tmp_path / "ev-b", "web02", {"/var/log/syslog": shared_path})
    case_dir = tmp_path / "case"
    assert cli.main(["case", str(host_a), str(host_b), "-o", str(case_dir)]) == 0
    record = _case_json(case_dir)
    assert all(e["type"] in ("ip", "domain", "url", "hash") for e in record["overlap"])


def test_case_bad_evidence_records_failure_and_continues(tmp_path, capsys):
    host_a, _ = _hosts(tmp_path)
    missing = tmp_path / "does-not-exist.tar.gz"
    case_dir = tmp_path / "case"
    code = cli.main(["case", str(host_a), str(missing), "-o", str(case_dir)])
    assert code != 0
    record = _case_json(case_dir)
    assert record["host_count"] == 2
    assert record["hosts"][0]["exit_code"] == 0
    assert record["hosts"][1]["exit_code"] != 0
    assert (case_dir / "hosts" / "web01" / "findings.json").is_file()
    assert "shared indicators" in capsys.readouterr().out


def test_case_single_host(tmp_path):
    (host_a, _) = _hosts(tmp_path)
    case_dir = tmp_path / "case"
    assert cli.main(["case", str(host_a), "-o", str(case_dir)]) == 0
    record = _case_json(case_dir)
    assert record["host_count"] == 1
    assert record["overlap"] == []


def test_compute_overlap_sorts_and_counts():
    iocs = {
        "web01": [
            {"type": "ip", "value": SHARED_IP, "defanged": "203[.]0[.]113[.]5", "sources": ["a", "b"]},
            {"type": "ip", "value": "10.0.0.1", "defanged": "10[.]0[.]0[.]1", "sources": ["c"]},
        ],
        "web02": [
            {"type": "ip", "value": SHARED_IP, "defanged": "203[.]0[.]113[.]5", "sources": ["d"]},
            {"type": "domain", "value": "evil.example.com", "defanged": "evil[.]example[.]com", "sources": ["e"]},
        ],
        "web03": [
            {"type": "ip", "value": SHARED_IP, "defanged": "203[.]0[.]113[.]5", "sources": ["f"]},
        ],
    }
    overlap, stats = compute_overlap(iocs)
    assert stats == {"indicators_seen": 3, "overlapping": 1, "truncated": False}
    assert len(overlap) == 1
    entry = overlap[0]
    assert entry["hosts"] == ["web01", "web02", "web03"]
    assert entry["host_count"] == 3
    assert entry["per_host"] == {"web01": 2, "web02": 1, "web03": 1}


def test_host_dir_helpers(tmp_path):
    assert sanitize_host_dir("web01.example.com", "x") == "web01.example.com"
    assert sanitize_host_dir("evil/host;`id`", "x") == "evil_host_id"
    assert sanitize_host_dir("", "fallback") == "fallback"
    assert sanitize_host_dir(None, "fallback") == "fallback"
    assert evidence_fallback_name("/tmp/web01.tar.gz") == "web01"
    assert evidence_fallback_name("/tmp/mini") == "mini"
    root = tmp_path / "hosts"
    root.mkdir()
    first = unique_host_dir(root, "web01", "fallback")
    assert first.name == "web01"
    first.mkdir()
    second = unique_host_dir(root, "web01", "fallback")
    assert second.name == "web01_2"
