"""Attacker-tool package installs (nmap, netcat, password crackers...).

Context-aware severity so base-image provisioning does not alert:
- explicit `apt install <tool>` naming the tool -> MEDIUM (as before);
- installed inside a bulk batch (>= threshold packages within the
  window, e.g. image build) -> INFO, batch size/time recorded;
- listed in default_image_packages and not explicitly requested -> INFO;
- pulled as an automatic dependency (apt history names other packages) -> LOW;
- dpkg-only record with no apt context -> MEDIUM (cannot rule out intent).

Thresholds, tool list and allowlist live in detection.toml (--config).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..config import load_config
from ..parsers.package_logs import parse_package_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "suspicious_package_install"

USES_CONFIG = True

RULE_INFO = {
    RULE: {
        "why": (
            "Scanners, netcat-style implants and password crackers installed via "
            "the package manager are the attacker's own tooling landing on the host."
        ),
        "next_steps": [
            "Determine who installed the tool (shell history, auth logs, apt history Commandline).",
            "INFO bulk-batch findings are usually image provisioning; confirm the batch timestamp "
            "matches a build/provisioning window before dismissing.",
            "Check whether the tool was executed and what it touched (firewall, listeners, captures).",
            "Remove the tool if it has no administrative justification.",
            "Tune detection.toml (bulk_batch, default_image_packages) for site-specific base images.",
        ],
    },
}

INSTALL_VERB_RE = re.compile(r"\binstall\b|\breinstall\b", re.IGNORECASE)


def _tool_pattern(tool: str) -> re.Pattern[str]:
    return re.compile(rf"(?:^|[-_.]){re.escape(tool)}(?:$|[-_.+]|\d)")


def _cmd_tool_pattern(tool: str) -> re.Pattern[str]:
    """Same component match, but tokens may also be whitespace-separated."""
    return re.compile(rf"(?:^|[\s\-_.]){re.escape(tool)}(?:$|[\s\-_.+]|\d|=)")


def _match_tool(name: str, tools: list[str]) -> str | None:
    lowered = name.lower()
    for tool in tools:
        if _tool_pattern(tool).search(lowered):
            return tool
    return None


def _commandline(message: str) -> str:
    _head, sep, tail = message.partition(" via ")
    return tail.strip() if sep else ""


def _explicitly_requested(commandline: str, tool: str) -> bool:
    if not commandline or not INSTALL_VERB_RE.search(commandline):
        return False
    after = INSTALL_VERB_RE.split(commandline, maxsplit=1)[1]
    return bool(_cmd_tool_pattern(tool).search(after))


def _mark_bulk(events: list[tuple[Event, dict]], threshold: int, window_seconds: int) -> dict[int, int]:
    """Map id(event) -> covering bulk-batch size for events inside a dense window."""
    dated = sorted(
        [(event.timestamp_utc, event) for event, _ in events if event.timestamp_utc is not None],
        key=lambda item: item[0],
    )
    covered: dict[int, int] = {}
    for start in range(len(dated)):
        end = start
        while end < len(dated) and (dated[end][0] - dated[start][0]).total_seconds() <= window_seconds:
            end += 1
        size = end - start
        if size >= threshold:
            for _, event in dated[start:end]:
                covered[id(event)] = max(covered.get(id(event), 0), size)
    return covered


def detect(events: Iterable[Event], config: dict | None = None) -> list[Finding]:
    cfg = config if config is not None else load_config()
    tools = list(cfg.get("package_tools", {}).get("tools", []))
    bulk_cfg = cfg.get("bulk_batch", {})
    threshold = int(bulk_cfg.get("threshold", 50))
    window_seconds = int(bulk_cfg.get("window_minutes", 10)) * 60
    allowlist = {name.lower() for name in cfg.get("default_image_packages", {}).get("packages", [])}

    parsed: list[tuple[Event, dict]] = []
    for event in events:
        if event.event_type not in ("package_install", "package_update"):
            continue
        info = parse_package_message(event.message)
        if info is None:
            continue
        tool = _match_tool(info["name"], tools)
        if tool is None:
            continue
        parsed.append((event, {**info, "tool": tool}))
    if not parsed:
        return []

    all_installs = [
        (event, None)
        for event in events
        if event.event_type in ("package_install", "package_update")
    ]
    bulk = _mark_bulk(all_installs, threshold, window_seconds)

    grouped: dict[str, dict] = {}
    for event, info in parsed:
        group = grouped.setdefault(info["tool"], {"events": [], "names": [], "batches": []})
        group["events"].append(event)
        if info["name"] not in group["names"]:
            group["names"].append(info["name"])
        if id(event) in bulk:
            group["batches"].append(bulk[id(event)])

    findings = []
    for tool in sorted(grouped):
        group = grouped[tool]
        names = sorted(group["names"])
        explicit = any(
            _explicitly_requested(_commandline(event.message), tool) for event in group["events"]
        )
        apt_sourced = any(_commandline(event.message) for event in group["events"])
        allowlisted = any(name.lower() in allowlist for name in names)
        first_seen = min(
            (event.timestamp_utc for event in group["events"] if event.timestamp_utc is not None),
            default=None,
        )
        refs = [Ref(event.evidence_path, event.line_or_offset) for event in group["events"]]
        if explicit:
            severity, why = Severity.MEDIUM, "explicitly requested via apt"
            mitre = ["T1588.002"]
        elif group["batches"]:
            biggest = max(group["batches"])
            when = first_seen.isoformat() if first_seen is not None else "unknown time"
            severity = Severity.INFO
            why = f"installed in a bulk batch of {biggest} packages within {threshold}-package window at {when}"
            mitre = ["T1588.002"]
        elif allowlisted:
            severity, why = Severity.INFO, "ships in default images (not explicitly requested)"
            mitre = ["T1588.002"]
        elif apt_sourced:
            severity = Severity.LOW
            cmds = sorted({_commandline(event.message) for event in group["events"] if _commandline(event.message)})
            why = f"automatic dependency, pulled by '{cmds[0][:160]}'" if cmds else "automatic dependency"
            mitre = ["T1588.002"]
        else:
            severity, why = Severity.MEDIUM, "no apt context to rule out manual install"
            mitre = ["T1588.002"]
        findings.append(
            Finding(
                id=make_finding_id(RULE, tool, ",".join(names)),
                rule=RULE,
                severity=severity,
                title=f"Attacker tool installed: {', '.join(names)} ({why})",
                description=(
                    f"{len(group['events'])} install/update record(s) for {tool}-family tooling "
                    f"[{why}]: " + " | ".join(event.message[:160] for event in group["events"][:4])
                ),
                mitre_ids=mitre,
                first_seen=first_seen,
                count=len(group["events"]),
                refs=refs,
            )
        )
    return findings
