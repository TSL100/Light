"""Regression tests: `run` uses the full parser pipeline; term.log is skipped."""

from __future__ import annotations

import gzip
import json

from conftest import make_mini_evidence

from linuxdfir import cli
from linuxdfir.ingest import Evidence
from linuxdfir.parsers import available_parsers, iter_members


def _parser_set(outdir):
    lines = (outdir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    return {json.loads(line)["parser"] for line in lines if line.strip()}


def _expected_parsers(archive):
    with Evidence.open(archive) as evidence:
        selected = available_parsers()
        return {
            name
            for name, module in selected.items()
            if list(iter_members(evidence, module.CONSUMES))
        }


def test_run_uses_all_parsers(generated, tmp_path, capsys):
    for profile in ("infected", "clean"):
        archive = generated["results"][profile]["archive"]
        run_out = tmp_path / f"run-{profile}"
        assert cli.main(["run", str(archive), "-o", str(run_out)]) == 0
        parse_out = tmp_path / f"parse-{profile}"
        assert cli.main(["parse", str(archive), "-o", str(parse_out)]) == 0
        assert _parser_set(run_out) == _parser_set(parse_out)
        run_stats = json.loads((run_out / "parse_stats.json").read_text(encoding="utf-8"))
        assert run_stats["parsers"] == sorted(available_parsers())
        assert set(run_stats["per_parser"]) == set(available_parsers())
        for name in _expected_parsers(archive):
            assert run_stats["per_parser"][name]["lines"] > 0, f"{profile}: {name} ran with no input"
    printed = capsys.readouterr().out
    assert printed.count("parsers          :") >= 4


def test_term_log_skipped(tmp_path):
    files = {
        "/var/log/apt/term.log": b"Setting up libc6 ...\nUnpacking foo ...\n",
        "/var/log/apt/term.log.1.gz": gzip.compress(b"more terminal output\n" * 50),
        "/var/log/dpkg.log": b"2026-01-02 03:20:11 install foo:amd64 1.0\n",
    }
    root = make_mini_evidence(tmp_path / "mini", files=files)
    out = tmp_path / "parsed"
    assert cli.main(["parse", str(root), "-o", str(out)]) == 0
    events = [
        json.loads(line)
        for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert events, "dpkg.log must still produce its event"
    assert all("term.log" not in event["evidence_path"] for event in events)
    stats = json.loads((out / "parse_stats.json").read_text(encoding="utf-8"))
    assert stats["parsers"] == sorted(available_parsers())
    assert len(stats["skipped"]) == 2
    assert all(entry["status"] == "not an event source" for entry in stats["skipped"])
    assert stats["per_parser"]["package_logs"]["unparsed"] == 0
    assert stats["per_parser"]["package_logs"]["events"] == 1


def test_no_hidden_dedup_or_dupes(generated, tmp_path):
    for profile in ("infected", "clean"):
        archive = generated["results"][profile]["archive"]
        out = tmp_path / f"parsed-{profile}"
        assert cli.main(["parse", str(archive), "-o", str(out)]) == 0
        stats = json.loads((out / "parse_stats.json").read_text(encoding="utf-8"))
        per_parser_total = sum(entry.get("events", 0) for entry in stats["members"])
        tl_stats = json.loads((out / "timeline_stats.json").read_text(encoding="utf-8"))
        assert per_parser_total == tl_stats["total"] == tl_stats["jsonl_events"], (
            f"{profile}: per-parser events ({per_parser_total}) != timeline total ({tl_stats['total']})"
        )
        seen = set()
        for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            key = (
                record["parser"],
                record["evidence_path"],
                str(record.get("line_or_offset")),
                record["message"],
            )
            assert key not in seen, f"{profile}: duplicate event {key}"
            seen.add(key)
