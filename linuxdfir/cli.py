"""linuxdfir command line interface."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .baseline import scan_with_baseline
from .case import (
    build_case_record,
    build_combined_timeline,
    compute_overlap,
    evidence_fallback_name,
    prepare_hosts_root,
    read_host_iocs,
    summarize_host,
    unique_host_dir,
)
from .config import load_config
from .correlate import correlate_findings
from .custody import current_argv, input_fingerprint, write_analysis_log
from .detectors import detect_all
from .ingest import Evidence, EvidenceError, UnsafeArchiveError
from .iocs import extract_iocs
from .merge import postprocess_findings
from .parsers import available_parsers, iter_members, skipped_members
from .report import csv_report, html, json_report
from .schema import Event, Finding, Severity
from .score import score_findings
from .sigma_scan import scan_with_rules_dir as scan_sigma_with_rules_dir
from .timeline import Timeline
from .yara_scan import scan_with_rules_dir

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTEGRITY = 2

_CONTROL_CHARS_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)


def term_safe(text: str) -> str:
    """Strip ANSI escapes and control characters before terminal output."""
    return _CONTROL_CHARS_RE.sub("", str(text))


class _Progress:
    """Throttled stderr progress; enabled by TTY or LINUXDFIR_PROGRESS=1."""

    def __init__(self, label: str, enabled: bool | None = None):
        if enabled is None:
            env = os.environ.get("LINUXDFIR_PROGRESS")
            enabled = env == "1" or (env is None and sys.stderr.isatty())
        self.label = label
        self.enabled = bool(enabled)
        self._last = 0.0

    def update(self, detail: str, *, force: bool = False) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and now - self._last < 1.0:
            return
        self._last = now
        print(f"[{self.label}] {detail}", file=sys.stderr, flush=True)


class EventFile:
    """Re-iterable event stream over events.jsonl.

    Every iteration re-reads and re-parses the file so detectors and the
    IOC/scoring passes never materialize the whole event set in RAM.
    ``count``/``skipped`` are recorded on the first full pass.
    """

    def __init__(self, path: Path):
        if path.is_dir():
            path = path / "events.jsonl"
        self.path = path
        self.count = 0
        self.skipped = 0
        self.passes = 0
        self._progress = _Progress("events")

    def __iter__(self):
        count = 0
        skipped = 0
        self.passes += 1
        self._progress.update(f"reading {self.path.name} (pass {self.passes})", force=True)
        with open(self.path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = Event.from_dict(json.loads(line))
                except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                    skipped += 1
                    continue
                count += 1
                if count % 1_000_000 == 0:
                    self._progress.update(f"pass {self.passes}: {count:,} events")
                yield event
        if self.passes == 1:
            self.count = count
            self.skipped = skipped
        self._progress.update(
            f"pass {self.passes} done: {count:,} events, {skipped} skipped", force=True
        )

    def load_all(self) -> list[Event]:
        """Materialize the whole event set in a single pass.

        ``detect`` runs ~20 detectors plus IOC extraction and scoring. If
        each consumer iterated the stream it would re-read and re-parse
        events.jsonl from disk once per consumer (measured: ~16.7s per pass
        per 1M events, so tens of minutes on 13M-event evidence). Reading it
        exactly once and handing every consumer the same list makes detect
        single-pass while keeping per-consumer memory identical to before.
        """
        events = list(self)
        self._progress.update(
            f"loaded {len(events):,} events into memory (single pass)",
            force=True,
        )
        return events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linuxdfir",
        description="LinuxDFIR analyzer: offline analysis of collector evidence.",
    )
    parser.add_argument("--version", action="version", version=f"linuxdfir {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify evidence integrity against the manifest")
    verify.add_argument("evidence", help="evidence.tar.gz file or an extracted evidence folder")
    verify.add_argument(
        "--report-dir",
        default=None,
        help="write verify_report.json into this directory (created if needed)",
    )
    verify.set_defaults(func=cmd_verify)
    parse = sub.add_parser("parse", help="parse evidence artifacts into events.jsonl")
    parse.add_argument("evidence", help="evidence.tar.gz file or an extracted evidence folder")
    parse.add_argument("-o", "--out", required=True, help="output directory for events.jsonl")
    parse.add_argument(
        "--parsers",
        default="all",
        help="comma-separated parser names or 'all' (default: all)",
    )
    parse.set_defaults(func=cmd_parse)
    detect = sub.add_parser("detect", help="run detections over events.jsonl")
    detect.add_argument("events", help="events.jsonl file or a directory containing it")
    detect.add_argument("-o", "--out", default=None, help="output directory for findings.json")
    detect.add_argument(
        "--config",
        default=None,
        help="detection tuning TOML (default: shipped detection.toml)",
    )
    detect.add_argument(
        "--yara-rules",
        default=None,
        help=(
            "folder of .yar/.yara rules to scan collected file contents "
            "(requires --evidence and yara-python; skipped cleanly if missing)"
        ),
    )
    detect.add_argument(
        "--evidence",
        default=None,
        help="evidence.tar.gz file or extracted folder to scan with --yara-rules",
    )
    detect.add_argument(
        "--sigma-rules",
        default=None,
        help=(
            "folder of Sigma .yml/.yaml rules to match against events "
            "(linux auth/syslog/auditd/process_creation subset; "
            "skipped cleanly if PyYAML is missing)"
        ),
    )
    detect.add_argument(
        "--baseline",
        default=None,
        help=(
            "clean-baseline source to diff against: events.jsonl, a directory "
            "holding it, or evidence to parse (additions/removals become findings)"
        ),
    )
    detect.set_defaults(func=cmd_detect)
    run = sub.add_parser("run", help="verify + parse + detect + report in one step")
    run.add_argument("evidence", help="evidence.tar.gz file or an extracted evidence folder")
    run.add_argument("-o", "--out", required=True, help="output directory")
    run.add_argument(
        "--parsers",
        default="all",
        help="comma-separated parser names or 'all' (default: all)",
    )
    run.add_argument(
        "--config",
        default=None,
        help="detection tuning TOML (default: shipped detection.toml)",
    )
    run.add_argument(
        "--yara-rules",
        default=None,
        help=(
            "folder of .yar/.yara rules to scan collected file contents "
            "(requires yara-python; skipped cleanly if missing)"
        ),
    )
    run.add_argument(
        "--sigma-rules",
        default=None,
        help=(
            "folder of Sigma .yml/.yaml rules to match against events "
            "(linux auth/syslog/auditd/process_creation subset; "
            "skipped cleanly if PyYAML is missing)"
        ),
    )
    run.add_argument(
        "--baseline",
        default=None,
        help=(
            "clean-baseline source to diff against: evidence archive/folder, "
            "events.jsonl, or a directory holding it"
        ),
    )
    run.set_defaults(func=cmd_run)
    case = sub.add_parser(
        "case",
        help="analyze several evidence archives into one case folder",
    )
    case.add_argument(
        "evidence",
        nargs="+",
        help="two or more evidence.tar.gz files or extracted evidence folders",
    )
    case.add_argument("-o", "--out", required=True, help="case directory (hosts/ rebuilt each run)")
    case.add_argument(
        "--parsers",
        default="all",
        help="comma-separated parser names or 'all' (default: all)",
    )
    case.add_argument(
        "--config",
        default=None,
        help="detection tuning TOML (default: shipped detection.toml)",
    )
    case.add_argument(
        "--yara-rules",
        default=None,
        help="folder of .yar/.yara rules applied to every host (skipped cleanly if missing)",
    )
    case.add_argument(
        "--sigma-rules",
        default=None,
        help="folder of Sigma .yml/.yaml rules applied to every host",
    )
    case.add_argument(
        "--baseline",
        default=None,
        help="clean-baseline source diffed against every host",
    )
    case.set_defaults(func=cmd_case)
    report = sub.add_parser("report", help="build report.html/findings.csv from a parsed output directory")
    report.add_argument("out", help="output directory holding events.jsonl/findings.json (from parse/detect or run)")
    report.add_argument("--report-name", default="report.html", help="report file name")
    report.set_defaults(func=cmd_report)
    secrets = sub.add_parser(
        "scan-secrets",
        help="scan collector output for accidental secret material before sharing",
    )
    secrets.add_argument("directory", help="collector output directory to scan recursively")
    secrets.add_argument(
        "-o", "--out", default=None, help="write scan_secrets.json into this directory"
    )
    secrets.add_argument(
        "--max-match-lines",
        type=int,
        default=5,
        help="maximum example lines to record per pattern (default: 5)",
    )
    secrets.set_defaults(func=cmd_scan_secrets)
    yara = sub.add_parser(
        "scan-yara",
        help="scan collected file contents with YARA rules (optional dependency)",
    )
    yara.add_argument("evidence", help="evidence.tar.gz file or an extracted evidence folder")
    yara.add_argument(
        "--rules",
        required=True,
        help="folder of .yar/.yara rule files (compiled together)",
    )
    yara.add_argument(
        "-o", "--out", default=None, help="output directory for yara_findings.json"
    )
    yara.add_argument(
        "--config",
        default=None,
        help="detection tuning TOML (default: shipped detection.toml)",
    )
    yara.add_argument(
        "--max-file-mb",
        type=int,
        default=None,
        help="skip files larger than this (default: [yara].max_file_mb from config)",
    )
    yara.set_defaults(func=cmd_scan_yara)
    sigma = sub.add_parser(
        "scan-sigma",
        help="match Sigma rules against events (optional PyYAML dependency)",
    )
    sigma.add_argument("events", help="events.jsonl file or a directory containing it")
    sigma.add_argument(
        "--rules",
        required=True,
        help="folder of Sigma .yml/.yaml rule files (linux subset is evaluated)",
    )
    sigma.add_argument(
        "-o", "--out", default=None, help="output directory for sigma_findings.json"
    )
    sigma.add_argument(
        "--config",
        default=None,
        help="detection tuning TOML (default: shipped detection.toml)",
    )
    sigma.set_defaults(func=cmd_scan_sigma)
    baseline_cmd = sub.add_parser(
        "scan-baseline",
        help="diff a target against a clean baseline (additions/removals as findings)",
    )
    baseline_cmd.add_argument(
        "target",
        help="target side: events.jsonl, a directory holding it, or evidence to parse",
    )
    baseline_cmd.add_argument(
        "--baseline",
        required=True,
        help="clean-baseline side: events.jsonl, a directory holding it, or evidence to parse",
    )
    baseline_cmd.add_argument(
        "-o", "--out", default=None, help="output directory for baseline_findings.json"
    )
    baseline_cmd.add_argument(
        "--config",
        default=None,
        help="detection tuning TOML (default: shipped detection.toml)",
    )
    baseline_cmd.set_defaults(func=cmd_scan_baseline)
    return parser


def _print_verify_summary(report: dict, findings: list) -> None:
    print(f"source           : {report['source']} ({report['kind']})")
    print(f"host             : {term_safe(str(report['hostname']))}")
    print(f"collected (UTC)  : {report['collection_time_utc']}")
    print(f"sidecar          : {report['sidecar']['status']}")
    counts = report["counts"]
    print(
        "entries ok/mismatch/missing/extra/metadata-only: "
        f"{counts['ok']} / {counts['mismatch']} / {counts['missing']} / "
        f"{counts['extra']} / {counts['metadata_only']}"
    )
    for key in ("mismatch", "missing", "extra"):
        for name in report[key]:
            print(f"  {key.upper():8} {term_safe(str(name))}")
    if findings:
        print(f"integrity findings : {len(findings)}")
        for finding in findings:
            print(f"  [{finding.severity.value.upper():8}] {term_safe(finding.title)}")
    print(f"integrity        : {'OK' if report['integrity_ok'] else 'FAILED'}")


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        with Evidence.open(args.evidence) as evidence:
            report = evidence.verify()
            findings = evidence.integrity_findings
    except (EvidenceError, UnsafeArchiveError) as exc:
        print(f"verify failed: {term_safe(exc)}", file=sys.stderr)
        return EXIT_INTEGRITY
    except OSError as exc:
        print(f"verify failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    _print_verify_summary(report, findings)
    if args.report_dir:
        outdir = Path(args.report_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "verify_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"report written   : {outdir / 'verify_report.json'}")
    return EXIT_OK if report["integrity_ok"] else EXIT_INTEGRITY


def resolve_parser_names(spec: str) -> tuple[list[str], dict]:
    """Resolve a --parsers spec to (names, registry). Raises ValueError on unknown names."""
    selected = available_parsers()
    names = [name.strip() for name in spec.split(",") if name.strip()]
    if "all" in names:
        names = sorted(selected)
    unknown = [name for name in names if name not in selected]
    if unknown:
        raise ValueError(f"unknown parser(s): {', '.join(unknown)}")
    return names, selected


def run_parse_pipeline(evidence: Evidence, outdir: Path, names: list[str], selected: dict) -> dict:
    """Shared parse pipeline used by both `parse` and `run`.

    Returns a summary dict with counts, per-parser aggregates, skipped
    (non-event-source) members and the raw per-member stats.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    member_stats: list[dict] = []
    progress = _Progress("parse")
    event_total = 0

    def generate():
        nonlocal event_total
        for name in names:
            module = selected[name]
            for member in iter_members(evidence, module.CONSUMES):
                stats: dict = {}
                progress.update(f"{name}: {member}")
                try:
                    for event in module.parse_member(evidence, member, stats=stats):
                        event_total += 1
                        if event_total % 500_000 == 0:
                            progress.update(f"{event_total:,} events parsed")
                        yield event
                except (EvidenceError, UnsafeArchiveError) as exc:
                    stats["error"] = str(exc)
                finally:
                    member_stats.append({"parser": name, **stats})
                    progress.update(
                        f"{name}: {member} done ({event_total:,} events)", force=True
                    )
            parse_manifest = getattr(module, "parse_manifest", None)
            if parse_manifest is not None:
                stats = {}
                try:
                    yield from parse_manifest(evidence, stats=stats)
                except (EvidenceError, UnsafeArchiveError) as exc:
                    stats["error"] = str(exc)
                finally:
                    member_stats.append({"parser": name, **stats})

    timeline = Timeline.build(
        outdir / "timeline.db",
        generate(),
        collection_time_utc=evidence.context.collection_time_utc,
    )
    with timeline:
        jsonl_count = timeline.write_jsonl(outdir / "events.jsonl")
        csv_count = timeline.write_csv(outdir / "timeline.csv")
        tl_stats = timeline.stats()
    (outdir / "manifest.json").write_text(
        json.dumps(evidence.manifest, indent=2) + "\n", encoding="utf-8"
    )
    skipped: list[dict] = []
    for member in skipped_members(evidence):
        progress.update(f"counting skipped member {member}", force=True)
        lines = 0
        try:
            for _lineno, _line in evidence.iter_lines(member):
                lines += 1
        except (EvidenceError, UnsafeArchiveError):
            pass
        skipped.append(
            {
                "parser": None,
                "member": member,
                "lines": lines,
                "events": 0,
                "unparsed": 0,
                "status": "not an event source",
            }
        )
    per_parser: dict[str, dict] = {}
    for name in names:
        lines = sum(entry.get("lines", 0) for entry in member_stats if entry.get("parser") == name)
        events = sum(entry.get("events", 0) for entry in member_stats if entry.get("parser") == name)
        unparsed = sum(entry.get("unparsed", 0) for entry in member_stats if entry.get("parser") == name)
        per_parser[name] = {
            "lines": lines,
            "events": events,
            "unparsed": unparsed,
            "unparsed_ratio": (unparsed / lines) if lines else 0.0,
        }
    errors = [entry for entry in member_stats if entry.get("error")]
    summary = {
        "parsers": names,
        "per_parser": per_parser,
        "skipped": skipped,
        "members": member_stats,
        "jsonl_events": jsonl_count,
        "csv_rows": csv_count,
        "dated": tl_stats["dated"],
        "undated": tl_stats["undated"],
        "suspicious_time": tl_stats["suspicious_time"],
        "parser_errors": errors,
        "parser_error_count": len(errors),
    }
    (outdir / "parse_stats.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (outdir / "timeline_stats.json").write_text(
        json.dumps(
            {
                **tl_stats,
                "jsonl_events": jsonl_count,
                "csv_rows": csv_count,
                "parser_errors": errors,
                "parser_error_count": len(errors),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return summary


def _print_parse_summary(outdir: Path, names: list[str], summary: dict) -> None:
    print(f"events           : {summary['jsonl_events']} -> {outdir / 'events.jsonl'}")
    print(f"timeline         : {summary['csv_rows']} rows -> {outdir / 'timeline.csv'} (+ timeline.db)")
    print(
        f"dated/undated/suspicious: {summary['dated']} / {summary['undated']} / "
        f"{summary['suspicious_time']}"
    )
    print(f"parsers          : {', '.join(names)}")
    for name in names:
        agg = summary["per_parser"][name]
        print(
            f"  {name}: {agg['lines']} lines, {agg['events']} events, "
            f"{agg['unparsed']} unparsed (ratio {agg['unparsed_ratio']:.3f})"
        )
    for entry in summary["members"]:
        if entry.get("error"):
            print(
                f"  {entry.get('parser')} {term_safe(str(entry.get('member')))}: "
                f"ERROR {term_safe(entry['error'])}"
            )
    for entry in summary["skipped"]:
        print(f"  skipped {term_safe(entry['member'])}: {entry['lines']} lines (not an event source)")


def cmd_parse(args: argparse.Namespace) -> int:
    started = datetime.now(UTC)
    try:
        evidence = Evidence.open(args.evidence)
    except (EvidenceError, UnsafeArchiveError) as exc:
        print(f"parse failed: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    with evidence:
        try:
            names, selected = resolve_parser_names(args.parsers)
        except ValueError as exc:
            print(f"parse failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        outdir = Path(args.out)
        summary = run_parse_pipeline(evidence, outdir, names, selected)
        _print_parse_summary(outdir, names, summary)
        kind, digest = input_fingerprint(args.evidence)
        write_analysis_log(
            outdir,
            argv=getattr(args, "_argv", None) or current_argv(None),
            evidence_source=args.evidence,
            evidence_kind=kind,
            input_sha256=digest,
            started_utc=started,
            ended_utc=datetime.now(UTC),
            config=None,
            config_source="not used (parse-only run)",
            parser_names=names,
        )
    return EXIT_OK


def _load_events(path: Path) -> EventFile:
    """Return a re-iterable event stream (no upfront materialization)."""
    stream = EventFile(path)
    if not stream.path.is_file():
        raise OSError(f"events file not found: {stream.path}")
    return stream


def _print_yara_summary(stats: dict) -> None:
    """One-line YARA outcome for detect/run/scan-yara output."""
    if stats.get("status") == "skipped":
        print(f"yara             : skipped ({term_safe(stats.get('reason', 'unavailable'))})")
        return
    print(
        f"yara             : {stats['matches']} match(es), "
        f"{stats['files_scanned']} file(s) scanned "
        f"({stats['files_skipped_too_large']} too large, "
        f"{stats['files_skipped_unreadable']} unreadable, "
        f"{stats['files_skipped_no_content']} metadata-only)"
    )


def _print_sigma_summary(stats: dict) -> None:
    """One-line Sigma outcome for detect/run/scan-sigma output."""
    if stats.get("status") == "skipped":
        print(f"sigma            : skipped ({term_safe(stats.get('reason', 'unavailable'))})")
        return
    print(
        f"sigma            : {stats['matches']} rule(s) matched, "
        f"{stats['total_hits']} hit(s) over {stats['events_scanned']} event(s) "
        f"({stats['rules_loaded']} rule(s) loaded, "
        f"{stats['rules_skipped_logsource']} skipped by logsource)"
    )


def _print_baseline_summary(stats: dict) -> None:
    """Multi-line baseline outcome for detect/run/scan-baseline output."""
    print(
        f"baseline         : {stats['findings']} drift finding(s), "
        f"{stats['compared']} of {len(stats['categories'])} categories compared "
        f"(target {term_safe(str(stats['target']))} vs baseline "
        f"{term_safe(str(stats['baseline']))})"
    )
    for rule, entry in stats["categories"].items():
        if entry["compared"]:
            print(
                f"  {rule}: baseline={entry['baseline_count']} target={entry['target_count']} "
                f"added={entry['added']} removed={entry['removed']}"
            )
        else:
            print(f"  {rule}: skipped (no coverage on {', '.join(entry['skipped_no_coverage'])})")


def _load_side_events(source: str | Path, workdir: Path) -> list[Event]:
    """Load events for one baseline side: parsed events or evidence to parse.

    ``source`` is events.jsonl, a directory holding it, or evidence
    (archive/folder) which is parsed with all parsers into ``workdir``.
    """
    path = Path(source)
    if path.is_file() and path.suffix == ".jsonl":
        return _load_events(path).load_all()
    if path.is_dir() and (path / "events.jsonl").is_file():
        return _load_events(path).load_all()
    with Evidence.open(path) as evidence:
        names, selected = resolve_parser_names("all")
        parsed_dir = workdir / "parsed"
        parsed_dir.mkdir(parents=True, exist_ok=True)
        run_parse_pipeline(evidence, parsed_dir, names, selected)
        return _load_events(parsed_dir).load_all()


def cmd_detect(args: argparse.Namespace) -> int:
    try:
        stream = _load_events(Path(args.events))
    except OSError as exc:
        print(f"detect failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        config = load_config(getattr(args, "config", None))
    except (OSError, ValueError) as exc:
        print(f"detect failed: bad config: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    try:
        events: list[Event] = stream.load_all()
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(
            f"detect failed: cannot read events from {stream.path} "
            f"(expected JSONL from `parse`): {term_safe(exc)}",
            file=sys.stderr,
        )
        return EXIT_ERROR
    progress = _Progress("detect")
    progress.update(f"running detectors over {len(events):,} events", force=True)
    yara_rules = getattr(args, "yara_rules", None)
    evidence_source = getattr(args, "evidence", None)
    if yara_rules and not evidence_source:
        print(
            "detect failed: --yara-rules requires --evidence "
            "(archive or folder whose file contents to scan)",
            file=sys.stderr,
        )
        return EXIT_ERROR
    base = detect_all(events, config=config)
    yara_stats: dict | None = None
    if yara_rules:
        try:
            with Evidence.open(evidence_source) as evidence:
                yara_findings, yara_stats = scan_with_rules_dir(evidence, yara_rules, config)
        except (EvidenceError, UnsafeArchiveError) as exc:
            print(f"detect failed: cannot open evidence for YARA scan: {term_safe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        except (OSError, ValueError) as exc:
            print(f"detect failed: YARA scan: {term_safe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        progress.update(
            f"yara scan: {len(yara_findings)} match(es) ({yara_stats['status']})", force=True
        )
        base.extend(yara_findings)
    sigma_stats: dict | None = None
    sigma_rules = getattr(args, "sigma_rules", None)
    if sigma_rules:
        try:
            sigma_findings, sigma_stats = scan_sigma_with_rules_dir(events, sigma_rules, config)
        except (OSError, ValueError) as exc:
            print(f"detect failed: Sigma scan: {term_safe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        progress.update(
            f"sigma scan: {len(sigma_findings)} rule(s) matched ({sigma_stats['status']})",
            force=True,
        )
        base.extend(sigma_findings)
    baseline_stats: dict | None = None
    baseline_source = getattr(args, "baseline", None)
    if baseline_source:
        try:
            if args.out:
                workdir = Path(args.out) / "baseline-work"
                workdir.mkdir(parents=True, exist_ok=True)
                baseline_events = _load_side_events(baseline_source, workdir)
            else:
                with tempfile.TemporaryDirectory(prefix="linuxdfir-baseline-") as tmp:
                    baseline_events = _load_side_events(baseline_source, Path(tmp))
            baseline_findings, baseline_stats = scan_with_baseline(
                events,
                baseline_events,
                config,
                target_label=str(getattr(args, "events", "target")),
                baseline_label=str(baseline_source),
            )
        except (EvidenceError, UnsafeArchiveError) as exc:
            print(f"detect failed: cannot open baseline: {term_safe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        except (OSError, ValueError) as exc:
            print(f"detect failed: baseline diff: {term_safe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        progress.update(
            f"baseline diff: {len(baseline_findings)} drift finding(s)", force=True
        )
        base.extend(baseline_findings)
    findings = postprocess_findings(base, config)
    info_count = sum(1 for finding in findings if finding.severity == Severity.INFO)
    real_count = len(findings) - info_count
    headline = f"{real_count} actionable + {info_count} info"
    if args.out:
        outdir = Path(args.out)
        try:
            outdir.mkdir(parents=True, exist_ok=True)
            json_report.require_free_space(outdir)
            json_report.write_findings(findings, outdir / "findings.json")
            progress.update("scanning events for IOCs", force=True)
            iocs = extract_iocs(events, findings, config)
            json_report.atomic_write_json(outdir / "iocs.json", iocs)
            correlation = correlate_findings(findings, config)
            json_report.atomic_write_json(outdir / "correlation.json", correlation)
            progress.update("computing risk scores", force=True)
            risk = score_findings(findings, events, config)
            json_report.atomic_write_json(outdir / "risk.json", risk)
        except (OSError, json_report.WriteError) as exc:
            print(f"detect failed while writing outputs: {term_safe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        print(f"findings         : {headline} -> {outdir / 'findings.json'}")
        print(
            f"iocs             : {len(iocs['external'])} external, "
            f"{len(iocs['internal'])} internal -> {outdir / 'iocs.json'}"
        )
        print(
            f"attack chains    : {len(correlation['chains'])} "
            f"-> {outdir / 'correlation.json'}"
        )
        host_scores = risk.get("hosts", {})
        for host_name, host_data in host_scores.items():
            print(
                f"risk score       : {host_name}={host_data['score']} "
                f"(raw {host_data['raw_score']}, cap {host_data['cap']}) "
                f"-> {outdir / 'risk.json'}"
            )
    else:
        print(f"findings         : {headline}")
    if yara_stats is not None:
        _print_yara_summary(yara_stats)
    if sigma_stats is not None:
        _print_sigma_summary(sigma_stats)
    if baseline_stats is not None:
        _print_baseline_summary(baseline_stats)
    if stream.skipped:
        print(f"skipped lines    : {stream.skipped}")
    for finding in sorted(findings, key=lambda f: (f.severity.value, f.rule)):
        refs = ", ".join(f"{ref.evidence_path}:{ref.line_or_offset}" for ref in finding.refs[:3])
        extra = f" (+{len(finding.refs) - 3} more)" if len(finding.refs) > 3 else ""
        print(f"  [{finding.severity.value.upper():8}] {finding.rule}: {term_safe(finding.title)}")
        print(f"           count={finding.count} mitre={','.join(finding.mitre_ids)} refs={term_safe(refs)}{extra}")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    outdir = Path(args.out)
    findings_path = outdir / "findings.json"
    if not findings_path.is_file():
        print(f"report failed: {findings_path} not found (run parse and detect first)", file=sys.stderr)
        return EXIT_ERROR
    try:
        findings = [Finding.from_dict(item) for item in json.loads(findings_path.read_text(encoding="utf-8"))]
        target = html.build_report(outdir, report_name=args.report_name)
        csv_report.write_csv(findings, outdir / "findings.csv")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"report failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"report           : {target}")
    print(f"findings csv     : {outdir / 'findings.csv'}")
    return EXIT_OK


# Patterns a collector run should never leak into shared outputs. Each entry
# is (label, regex); the redaction markers themselves (`[REDACTED-`) are
# expected and ignored so a correctly-redacted run scans clean.
_SECRET_SCANS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("modular-crypt hash", re.compile(r"\$(?:2[aby]|[156]|y)\$[^\s$:]+(?:\$[^\s$:]+)+")),
    ("crypt hash field", re.compile(r"(?<![\w$])\$[^\s$:]{13,}\$[^\s$:]{13,}(?!\w)")),
    ("ssh private key", re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----")),
    ("sshpass -p", re.compile(r"\bsshpass\b[^\n]*?\s-p(?!ort\b)\s+(\"[^\"]+\"|'[^']+'|\S+)")),
    (
        "password assignment",
        re.compile(
            r"(?<![A-Za-z0-9_-])(?:--)?passw(?:or)?d[= ][\"']?"
            r"(?!\[REDACTED-)([^\s\"'()]{6,})"
        ),
    ),
    ("mysql -p", re.compile(r"\bmysql\b[^\n]*?\s-p(?!ort\b|assword)(\"[^\"]+\"|'[^']+'|\S+)")),
    ("curl -u creds", re.compile(r"\bcurl\b[^\n]*?(?:-u|--user)\s+[^\s:]+:(\S+)")),
    ("bearer token", re.compile(r"\bBearer\s+(?!\[REDACTED-)([A-Za-z0-9\-._~+/]{20,}=*)")),
    ("basic auth", re.compile(r"Authorization:\s*Basic\s+(?!\[REDACTED-)([A-Za-z0-9+/=]{16,})")),
    ("url credentials", re.compile(r"(?:https?|ftp)://[^/\s:@?#]+:([^/\s@?#]{4,})@")),
    ("password query", re.compile(r"[?&](?:password|passwd|pwd|secret|token)=([^&\s\"']{4,})")),
    ("api key query", re.compile(r"[?&](?:api[_-]?key|access[_-]?key|auth[_-]?token)=([^&\s\"']{12,})")),
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("generic api key", re.compile(r"\b(?:sk|pk|api)[_-][A-Za-z0-9]{20,}\b")),
)

_SCAN_TEXT_LIMIT = 2 * 1024 * 1024
_SCAN_BINARY_EXTS = {
    ".gz", ".xz", ".zst", ".bz2", ".zip", ".7z", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".pdf", ".db", ".sqlite", ".sqlite3", ".so", ".ko", ".bin", ".pyc",
}


def _scan_text_for_secrets(text: str, max_lines: int) -> list[dict]:
    """Return secret-pattern hits with redacted previews; never echoes secrets."""
    import hashlib

    def _fp(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:8]

    hits: list[dict] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for label, pattern in _SECRET_SCANS:
            for match in pattern.finditer(line):
                secret = next((g for g in match.groups() if g), match.group(0))
                if secret.startswith("[REDACTED-"):
                    continue
                # Preview masks everything after the pattern's literal prefix.
                start = max(match.start(), 0)
                prefix_len = match.end() - match.start() - len(secret)
                preview = (
                    line[max(0, start - 20): start + max(prefix_len, 0)]
                    + f"[REDACTED-{label.upper()}:{_fp(secret)}]"
                )
                hits.append({"line": lineno, "kind": label, "preview": preview[:200]})
                if len([h for h in hits if h["kind"] == label]) >= max_lines:
                    return hits
    return hits


def cmd_scan_secrets(args: argparse.Namespace) -> int:
    root = Path(args.directory)
    if not root.is_dir():
        print(f"scan-secrets failed: not a directory: {root}", file=sys.stderr)
        return EXIT_ERROR
    max_lines = max(1, args.max_match_lines)
    scanned = 0
    skipped = 0
    findings: list[dict] = []
    progress = _Progress("scan-secrets")
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in _SCAN_BINARY_EXTS or path.stat().st_size > _SCAN_TEXT_LIMIT:
            skipped += 1
            continue
        scanned += 1
        if scanned % 200 == 0:
            progress.update(f"scanned {scanned} files, {len(findings)} hits")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        hits = _scan_text_for_secrets(text, max_lines)
        if hits:
            findings.append(
                {
                    "file": str(path.relative_to(root)),
                    "hits": hits,
                    "total_hits": len(hits),
                }
            )
    report = {
        "directory": str(root),
        "files_scanned": scanned,
        "files_skipped": skipped,
        "files_with_hits": len(findings),
        "total_hits": sum(f["total_hits"] for f in findings),
        "findings": findings,
    }
    print(f"files scanned    : {scanned} (skipped {skipped} binary/oversize)")
    print(f"files with hits  : {len(findings)}")
    print(f"total secret hits: {report['total_hits']}")
    for finding in findings:
        print(f"  {finding['file']}: {finding['total_hits']} hit(s)")
        for hit in finding["hits"]:
            print(f"    line {hit['line']} [{hit['kind']}] {term_safe(hit['preview'])}")
    if args.out:
        outdir = Path(args.out)
        try:
            outdir.mkdir(parents=True, exist_ok=True)
            json_report.atomic_write_json(outdir / "scan_secrets.json", report)
        except (OSError, json_report.WriteError) as exc:
            print(f"scan-secrets failed while writing outputs: {term_safe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        print(f"report           : {outdir / 'scan_secrets.json'}")
    return EXIT_OK


def cmd_scan_yara(args: argparse.Namespace) -> int:
    try:
        config = load_config(getattr(args, "config", None))
    except (OSError, ValueError) as exc:
        print(f"scan-yara failed: bad config: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    try:
        with Evidence.open(args.evidence) as evidence:
            findings, stats = scan_with_rules_dir(
                evidence, args.rules, config, max_file_mb=getattr(args, "max_file_mb", None)
            )
    except (EvidenceError, UnsafeArchiveError) as exc:
        print(f"scan-yara failed: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    except (OSError, ValueError) as exc:
        print(f"scan-yara failed: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    _print_yara_summary(stats)
    for finding in sorted(findings, key=lambda f: (f.severity.value, f.rule)):
        refs = ", ".join(f"{ref.evidence_path}:{ref.line_or_offset}" for ref in finding.refs[:3])
        print(f"  [{finding.severity.value.upper():8}] {finding.rule}: {term_safe(finding.title)}")
        print(f"           count={finding.count} mitre={','.join(finding.mitre_ids)} refs={term_safe(refs)}")
    if args.out:
        outdir = Path(args.out)
        try:
            outdir.mkdir(parents=True, exist_ok=True)
            json_report.require_free_space(outdir)
            json_report.atomic_write_json(
                outdir / "yara_findings.json",
                {
                    "status": stats["status"],
                    "rules_dir": stats.get("rules_dir"),
                    "rules_files": stats.get("rules_files", []),
                    "stats": stats,
                    "findings": [finding.to_dict() for finding in findings],
                },
            )
        except (OSError, json_report.WriteError) as exc:
            print(f"scan-yara failed while writing outputs: {term_safe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        print(f"report           : {outdir / 'yara_findings.json'}")
    return EXIT_OK


def cmd_scan_sigma(args: argparse.Namespace) -> int:
    try:
        stream = _load_events(Path(args.events))
    except OSError as exc:
        print(f"scan-sigma failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        config = load_config(getattr(args, "config", None))
    except (OSError, ValueError) as exc:
        print(f"scan-sigma failed: bad config: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    try:
        events: list[Event] = stream.load_all()
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(
            f"scan-sigma failed: cannot read events from {stream.path} "
            f"(expected JSONL from `parse`): {term_safe(exc)}",
            file=sys.stderr,
        )
        return EXIT_ERROR
    try:
        findings, stats = scan_sigma_with_rules_dir(events, args.rules, config)
    except (OSError, ValueError) as exc:
        print(f"scan-sigma failed: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    _print_sigma_summary(stats)
    for finding in sorted(findings, key=lambda f: (f.severity.value, f.rule)):
        refs = ", ".join(f"{ref.evidence_path}:{ref.line_or_offset}" for ref in finding.refs[:3])
        print(f"  [{finding.severity.value.upper():8}] {finding.rule}: {term_safe(finding.title)}")
        print(f"           count={finding.count} mitre={','.join(finding.mitre_ids)} refs={term_safe(refs)}")
    if args.out:
        outdir = Path(args.out)
        try:
            outdir.mkdir(parents=True, exist_ok=True)
            json_report.require_free_space(outdir)
            json_report.atomic_write_json(
                outdir / "sigma_findings.json",
                {
                    "status": stats["status"],
                    "rules_dir": stats.get("rules_dir"),
                    "rules_files": stats.get("rules_files", []),
                    "stats": stats,
                    "findings": [finding.to_dict() for finding in findings],
                },
            )
        except (OSError, json_report.WriteError) as exc:
            print(f"scan-sigma failed while writing outputs: {term_safe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        print(f"report           : {outdir / 'sigma_findings.json'}")
    return EXIT_OK


def cmd_scan_baseline(args: argparse.Namespace) -> int:
    try:
        config = load_config(getattr(args, "config", None))
    except (OSError, ValueError) as exc:
        print(f"scan-baseline failed: bad config: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    try:
        if args.out:
            workdir = Path(args.out) / "baseline-work"
        else:
            workdir = Path(tempfile.mkdtemp(prefix="linuxdfir-baseline-"))
        workdir.mkdir(parents=True, exist_ok=True)
        target_events = _load_side_events(args.target, workdir / "target")
        baseline_events = _load_side_events(args.baseline, workdir / "baseline")
        findings, stats = scan_with_baseline(
            target_events,
            baseline_events,
            config,
            target_label=str(args.target),
            baseline_label=str(args.baseline),
        )
    except (EvidenceError, UnsafeArchiveError) as exc:
        print(f"scan-baseline failed: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    except (OSError, ValueError) as exc:
        print(f"scan-baseline failed: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    _print_baseline_summary(stats)
    for finding in sorted(findings, key=lambda f: (f.severity.value, f.rule)):
        refs = ", ".join(f"{ref.evidence_path}:{ref.line_or_offset}" for ref in finding.refs[:3])
        print(f"  [{finding.severity.value.upper():8}] {finding.rule}: {term_safe(finding.title)}")
        print(f"           count={finding.count} mitre={','.join(finding.mitre_ids)} refs={term_safe(refs)}")
    if args.out:
        outdir = Path(args.out)
        try:
            outdir.mkdir(parents=True, exist_ok=True)
            json_report.require_free_space(outdir)
            json_report.atomic_write_json(
                outdir / "baseline_findings.json",
                {
                    "status": stats["status"],
                    "target": stats.get("target"),
                    "baseline": stats.get("baseline"),
                    "stats": stats,
                    "findings": [finding.to_dict() for finding in findings],
                },
            )
        except (OSError, json_report.WriteError) as exc:
            print(f"scan-baseline failed while writing outputs: {term_safe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        print(f"report           : {outdir / 'baseline_findings.json'}")
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    started = datetime.now(UTC)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    argv = getattr(args, "_argv", None) or current_argv(None)
    verify_code = cmd_verify(argparse.Namespace(evidence=args.evidence, report_dir=str(outdir)))
    parse_code = cmd_parse(
        argparse.Namespace(
            evidence=args.evidence,
            out=str(outdir),
            parsers=args.parsers,
            _argv=argv,
        )
    )
    if parse_code != EXIT_OK:
        return parse_code
    detect_code = cmd_detect(
        argparse.Namespace(
            events=str(outdir),
            out=str(outdir),
            config=args.config,
            yara_rules=getattr(args, "yara_rules", None),
            evidence=args.evidence,
            sigma_rules=getattr(args, "sigma_rules", None),
            baseline=getattr(args, "baseline", None),
        )
    )
    if detect_code != EXIT_OK:
        return detect_code
    report_code = cmd_report(argparse.Namespace(out=str(outdir), report_name="report.html"))
    if report_code != EXIT_OK:
        return report_code
    final_code = EXIT_INTEGRITY if verify_code == EXIT_INTEGRITY else EXIT_OK
    try:
        names, _ = resolve_parser_names(args.parsers)
    except ValueError:
        names = sorted(available_parsers())
    try:
        config = load_config(args.config)
        config_source = args.config or "shipped detection.toml"
    except (OSError, ValueError):
        config, config_source = None, args.config or "shipped detection.toml"
    kind, digest = input_fingerprint(args.evidence)
    write_analysis_log(
        outdir,
        argv=argv,
        evidence_source=args.evidence,
        evidence_kind=kind,
        input_sha256=digest,
        started_utc=started,
        ended_utc=datetime.now(UTC),
        config=config,
        config_source=config_source,
        parser_names=names,
        exit_code=final_code,
    )
    return final_code


def _read_case_hostname(host_dir: Path) -> str | None:
    try:
        manifest = json.loads((host_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    hostname = manifest.get("hostname")
    return str(hostname) if hostname else None


def _print_case_summary(record: dict) -> None:
    print(f"hosts            : {record['host_count']}")
    for host in record["hosts"]:
        print(
            f"  {host['outdir']}: exit={host['exit_code']} "
            f"integrity={host['integrity_ok']} risk={host['risk_score']} "
            f"findings={host['findings_total']} ({host['findings_actionable']} actionable) "
            f"<- {term_safe(str(host['evidence']))}"
        )
    overlap = record["overlap"]
    print(f"shared indicators: {len(overlap)} (external ip/domain/url/hash on 2+ hosts)")
    for entry in overlap[:10]:
        print(
            f"  [{entry['type']}] {term_safe(str(entry['value']))} "
            f"on {entry['host_count']} hosts: {', '.join(entry['hosts'])}"
        )
    if len(overlap) > 10:
        print(f"  ... and {len(overlap) - 10} more (see case.json)")
    timeline = record["timeline"]
    print(
        f"combined timeline: {timeline['rows']} rows over {len(timeline['hosts'])} host(s) "
        f"-> {term_safe(str(timeline['path_csv']))}"
    )
    print(f"case record      : {term_safe(str(record.get('path', 'case.json')))}")


def cmd_case(args: argparse.Namespace) -> int:
    case_dir = Path(args.out)
    try:
        case_dir.mkdir(parents=True, exist_ok=True)
        json_report.require_free_space(case_dir)
        # Fail fast on a bad --config instead of after the first host run.
        load_config(getattr(args, "config", None))
    except (OSError, ValueError) as exc:
        print(f"case failed: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    argv = getattr(args, "_argv", None) or current_argv(None)
    try:
        hosts_root = prepare_hosts_root(case_dir)
    except OSError as exc:
        print(f"case failed: cannot prepare hosts directory: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    summaries: list[dict] = []
    worst = EXIT_OK
    for index, source in enumerate(args.evidence):
        pending = hosts_root / f"__pending_{index}"
        try:
            code = cmd_run(
                argparse.Namespace(
                    evidence=source,
                    out=str(pending),
                    parsers=args.parsers,
                    config=args.config,
                    _argv=argv,
                    yara_rules=getattr(args, "yara_rules", None),
                    sigma_rules=getattr(args, "sigma_rules", None),
                    baseline=getattr(args, "baseline", None),
                )
            )
        except (OSError, ValueError) as exc:
            print(f"case: host {term_safe(str(source))} failed: {term_safe(exc)}", file=sys.stderr)
            code = EXIT_ERROR
        worst = max(worst, code)
        try:
            hostname = _read_case_hostname(pending)
            final = unique_host_dir(hosts_root, hostname, evidence_fallback_name(source))
            if final != pending:
                pending.rename(final)
        except OSError as exc:
            print(f"case: cannot finalize host directory: {term_safe(exc)}", file=sys.stderr)
            final = pending
            worst = max(worst, EXIT_ERROR)
        summaries.append(summarize_host(final, str(source), code))
    participants = {
        entry["outdir"]: hosts_root / entry["outdir"]
        for entry in summaries
        if (hosts_root / entry["outdir"] / "events.jsonl").is_file()
    }
    host_iocs = {name: read_host_iocs(path) for name, path in participants.items()}
    overlap, overlap_stats = compute_overlap(host_iocs)
    try:
        timeline_stats = build_combined_timeline(
            participants,
            case_dir / "combined_timeline.db",
            case_dir / "combined_timeline.csv",
            case_dir / "combined_events.jsonl",
        )
        timeline_stats["path_db"] = str(case_dir / "combined_timeline.db")
        timeline_stats["path_csv"] = str(case_dir / "combined_timeline.csv")
        timeline_stats["path_jsonl"] = str(case_dir / "combined_events.jsonl")
        record = build_case_record(summaries, overlap, overlap_stats, timeline_stats, argv)
        record["path"] = str(case_dir / "case.json")
        json_report.atomic_write_json(case_dir / "case.json", record)
    except (OSError, json_report.WriteError, ValueError) as exc:
        print(f"case failed while writing case outputs: {term_safe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    _print_case_summary(record)
    return worst


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args._argv = current_argv(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
