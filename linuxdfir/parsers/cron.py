"""Cron parser: system crontabs, cron.d, run-parts dirs, spool files, anacrontab.

Also consumes live `crontab -l` snapshots (spool format, user from the
`crontab_<user>` file name). Emits one event per job with schedule, user
and command, plus cron_env events for variable assignments.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath

from ..ingest import Evidence
from ..schema import Event

PARSER_NAME = "cron"
CONSUMES = ["cron", "live_crontab"]

SYSTEM_JOB_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$")
SYSTEM_AT_RE = re.compile(r"^(@\S+)\s+(\S+)\s+(.+)$")
SPOOL_JOB_RE = re.compile(r"^(@\S+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$")
ENV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
ANACRON_JOB_RE = re.compile(r"^(\d+)\s+(\d+)\s+(\S+)\s+(.+)$")
LIVE_USER_RE = re.compile(r"^crontab_(.+)\.txt$")
AT_SCHEDULES = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@hourly"}
CRON_MESSAGE_RE = re.compile(r"^cron \[(.+?)\] (\S+?): (.+)$")


def parse_cron_message(message: str) -> dict | None:
    """Split a canonical cron_job message into schedule/user/command."""
    match = CRON_MESSAGE_RE.match(message)
    if not match:
        return None
    schedule, user, command = match.groups()
    return {"schedule": schedule, "user": user, "command": command}

RUN_PARTS_SCHEDULE = {
    "cron.hourly": "@hourly (run-parts)",
    "cron.daily": "@daily (run-parts)",
    "cron.weekly": "@weekly (run-parts)",
    "cron.monthly": "@monthly (run-parts)",
}


def _spool_user(member: str, display: str) -> str | None:
    if member.startswith("live/"):
        match = LIVE_USER_RE.match(PurePosixPath(member).name)
        if match:
            return match.group(1)
    return PurePosixPath(display).name or None


def _run_parts_kind(display: str) -> str | None:
    parts = PurePosixPath(display).parts
    for part in parts:
        if part in RUN_PARTS_SCHEDULE:
            return part
    return None


def _job_event(evidence, member, display, lineno, line, schedule, user, command) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=user,
        source_artifact="cron",
        event_type="cron_job",
        message=f"cron [{schedule}] {user}: {command}",
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["cron", "persistence"],
        confidence=1.0,
        parser=PARSER_NAME,
    )


def _env_event(evidence, member, display, lineno, line, name, value, user) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=user,
        source_artifact="cron",
        event_type="cron_env",
        message=f"cron env {name}={value}",
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["cron"],
        confidence=1.0,
        parser=PARSER_NAME,
    )


def _unparsed(evidence, member, display, lineno, line) -> Event:
    return Event(
        timestamp_utc=None,
        host=evidence.context.hostname,
        user=None,
        source_artifact="cron",
        event_type="unparsed",
        message=line.strip()[:500],
        evidence_path=display,
        line_or_offset=lineno,
        raw=line,
        tags=["unparsed"],
        confidence=0.1,
        parser=PARSER_NAME,
    )


def parse_member(evidence: Evidence, member: str, stats: dict | None = None) -> Iterator[Event]:
    if stats is None:
        stats = {}
    stats.update({"member": member, "lines": 0, "events": 0, "unparsed": 0})
    display = evidence.display_path(member)
    run_parts = _run_parts_kind(display)
    is_anacron = PurePosixPath(display).name == "anacrontab"
    is_spool = "/var/spool/cron" in display or member.startswith("live/")
    script_emitted = False
    for lineno, line in evidence.iter_lines(member):
        stats["lines"] += 1
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if run_parts is not None:
            if not script_emitted:
                script_emitted = True
                stats["events"] += 1
                yield _job_event(
                    evidence, member, display, 1, line,
                    RUN_PARTS_SCHEDULE[run_parts], "root", display,
                )
            continue
        env = ENV_RE.match(text)
        if env is not None:
            name, value = env.group(1), env.group(2).strip()
            user = _spool_user(member, display) if is_spool else None
            stats["events"] += 1
            yield _env_event(evidence, member, display, lineno, line, name, value, user)
            continue
        if is_anacron:
            job = ANACRON_JOB_RE.match(text)
            if job is not None:
                period, delay, job_id, command = job.groups()
                stats["events"] += 1
                yield _job_event(
                    evidence, member, display, lineno, line,
                    f"every {period}d +{delay}min ({job_id})", "root", command.strip(),
                )
                continue
        elif not is_spool:
            at_job = SYSTEM_AT_RE.match(text)
            if at_job is not None:
                schedule, user, command = at_job.groups()
                if command.strip():
                    stats["events"] += 1
                    yield _job_event(
                        evidence, member, display, lineno, line, schedule, user, command.strip()
                    )
                    continue
            job = SYSTEM_JOB_RE.match(text)
            if job is not None:
                minute, hour, dom, month, dow, user, command = job.groups()
                if command.strip():
                    stats["events"] += 1
                    yield _job_event(
                        evidence, member, display, lineno, line,
                        f"{minute} {hour} {dom} {month} {dow}", user, command.strip(),
                    )
                    continue
        else:
            spool = SPOOL_JOB_RE.match(text)
            if spool is not None:
                schedule, command = spool.groups()
                if command.strip():
                    stats["events"] += 1
                    yield _job_event(
                        evidence, member, display, lineno, line,
                        schedule.strip(), _spool_user(member, display), command.strip(),
                    )
                    continue
        stats["events"] += 1
        stats["unparsed"] += 1
        yield _unparsed(evidence, member, display, lineno, line)
