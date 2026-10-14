"""linuxdfir command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .detectors import detect_all
from .ingest import Evidence, EvidenceError, UnsafeArchiveError
from .parsers import available_parsers, iter_members, skipped_members
from .report import csv_report, html, json_report
from .schema import Event, Finding
from .timeline import Timeline

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTEGRITY = 2


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
    run.set_defaults(func=cmd_run)
    report = sub.add_parser("report", help="build report.html/findings.csv from a parsed output directory")
    report.add_argument("out", help="output directory holding events.jsonl/findings.json (from parse/detect or run)")
    report.add_argument("--report-name", default="report.html", help="report file name")
    report.set_defaults(func=cmd_report)
    return parser


def _print_verify_summary(report: dict, findings: list) -> None:
    print(f"source           : {report['source']} ({report['kind']})")
    print(f"host             : {report['hostname']}")
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
            print(f"  {key.upper():8} {name}")
    if findings:
        print(f"integrity findings : {len(findings)}")
        for finding in findings:
            print(f"  [{finding.severity.value.upper():8}] {finding.title}")
    print(f"integrity        : {'OK' if report['integrity_ok'] else 'FAILED'}")


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        with Evidence.open(args.evidence) as evidence:
            report = evidence.verify()
            findings = evidence.integrity_findings
    except (EvidenceError, UnsafeArchiveError) as exc:
        print(f"verify failed: {exc}", file=sys.stderr)
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

    def generate():
        for name in names:
            module = selected[name]
            for member in iter_members(evidence, module.CONSUMES):
                stats: dict = {}
                try:
                    yield from module.parse_member(evidence, member, stats=stats)
                except (EvidenceError, UnsafeArchiveError) as exc:
                    stats["error"] = str(exc)
                finally:
                    member_stats.append({"parser": name, **stats})
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
            print(f"  {entry.get('parser')} {entry.get('member')}: ERROR {entry['error']}")
    for entry in summary["skipped"]:
        print(f"  skipped {entry['member']}: {entry['lines']} lines (not an event source)")


def cmd_parse(args: argparse.Namespace) -> int:
    try:
        evidence = Evidence.open(args.evidence)
    except (EvidenceError, UnsafeArchiveError) as exc:
        print(f"parse failed: {exc}", file=sys.stderr)
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
    return EXIT_OK


def _load_events(path: Path) -> list[Event]:
    if path.is_dir():
        path = path / "events.jsonl"
    events = []
    skipped = 0
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(Event.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                skipped += 1
    return events, skipped


def cmd_detect(args: argparse.Namespace) -> int:
    try:
        events, skipped = _load_events(Path(args.events))
    except OSError as exc:
        print(f"detect failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        config = load_config(getattr(args, "config", None))
    except (OSError, ValueError) as exc:
        print(f"detect failed: bad config: {exc}", file=sys.stderr)
        return EXIT_ERROR
    findings = detect_all(events, config=config)
    if args.out:
        outdir = Path(args.out)
        outdir.mkdir(parents=True, exist_ok=True)
        json_report.write_findings(findings, outdir / "findings.json")
        print(f"findings         : {len(findings)} -> {outdir / 'findings.json'}")
    else:
        print(f"findings         : {len(findings)}")
    if skipped:
        print(f"skipped lines    : {skipped}")
    for finding in sorted(findings, key=lambda f: (f.severity.value, f.rule)):
        refs = ", ".join(f"{ref.evidence_path}:{ref.line_or_offset}" for ref in finding.refs[:3])
        extra = f" (+{len(finding.refs) - 3} more)" if len(finding.refs) > 3 else ""
        print(f"  [{finding.severity.value.upper():8}] {finding.rule}: {finding.title}")
        print(f"           count={finding.count} mitre={','.join(finding.mitre_ids)} refs={refs}{extra}")
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


def cmd_run(args: argparse.Namespace) -> int:
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    verify_code = cmd_verify(argparse.Namespace(evidence=args.evidence, report_dir=str(outdir)))
    parse_code = cmd_parse(
        argparse.Namespace(evidence=args.evidence, out=str(outdir), parsers=args.parsers)
    )
    if parse_code != EXIT_OK:
        return parse_code
    detect_code = cmd_detect(
        argparse.Namespace(events=str(outdir), out=str(outdir), config=args.config)
    )
    if detect_code != EXIT_OK:
        return detect_code
    report_code = cmd_report(argparse.Namespace(out=str(outdir), report_name="report.html"))
    if report_code != EXIT_OK:
        return report_code
    return EXIT_INTEGRITY if verify_code == EXIT_INTEGRITY else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
