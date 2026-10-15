"""Offensive-tool and tunnel-tool paths observed in triage listings.

Well-known offensive-security project directories (C2 frameworks, phishing
kits) and tunnel/proxy clients (cloudflared, ngrok, frp, chisel, ligolo)
leave distinctive path components when staged on a host, e.g.
``/root/evilgophish-1``, ``/root/evilginx``, ``/opt/cloudflared``.

The finding records the observation only: presence of such a path does not
establish who placed it — red-team assessments and malicious operations
both leave these artifacts, and the analyst decides. Executables rate LOW,
non-executable files and directories INFO. These findings are deliberately
NOT subject to the timestomp provenance allowlist: a package/cache path
prefix explains timestamp drift, not the presence of offensive tooling.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..config import load_config
from ..parsers.filesystem_suspicious import parse_fs_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "offensive_tool_paths"

USES_CONFIG = True

RULE_INFO = {
    RULE: {
        "why": (
            "C2 frameworks, phishing kits and tunnel clients stage in "
            "distinctive project directories whose names survive triage "
            "listings. Their presence is a strong pivot point for the rest "
            "of the investigation even though presence alone does not "
            "attribute the operator."
        ),
        "next_steps": [
            "Inventory every file under the tool directory and hash it against known-good releases.",
            "Check cron, systemd and shell history for how the tool was launched and persisted.",
            "For tunnel clients, review listening sockets and outbound connections at the collection time.",
            "Correlate the tool's ctime with logins and package installs around the same window.",
        ],
    },
}

FS_EVENT_TYPES = ("recent_file", "tmp_area_file", "hidden_file", "suid_sgid_file")

# Project/directory names of well-known offensive frameworks and phishing
# kits. Matched case-insensitively as a path-component prefix, so
# ``evilgophish-1`` matches ``evilgophish``.
OFFENSIVE_TOOL_NAMES = (
    "evilginx",
    "evilgophish",
    "gophish",
    "mythic",
    "covenant",
    "sliver",
    "havoc",
    "bruteratel",
    "cobaltstrike",
    "cobalt-strike",
    "metasploit",
    "msfvenom",
    "ligolo",
    "sharpsploit",
    "ghostpack",
)

# Tunnel/proxy clients commonly used for ingress through egress-filtered
# networks.
TUNNEL_TOOL_NAMES = (
    "cloudflared",
    "ngrok",
    "frpc",
    "frps",
    "localtunnel",
    "chisel",
    "gost",
    "neo-regeorg",
    "reGeorg",
    "plink",
)


def _executable(fields: dict) -> bool:
    mode = fields.get("mode", "")
    if mode.startswith("0o") or mode.startswith("0O"):
        try:
            return bool(int(mode, 8) & 0o111)
        except ValueError:
            return False
    return "x" in mode


def _match_tool(path: str, names: tuple[str, ...]) -> str | None:
    lowered_parts = [part.lower() for part in path.split("/") if part]
    for part in lowered_parts:
        stripped = part[1:] if part.startswith(".") else part
        for name in names:
            if part == name or part.startswith(name) or stripped.startswith(name):
                return name
    return None


def detect(events: Iterable[Event], config: dict | None = None) -> list[Finding]:
    cfg = config if config is not None else load_config()
    tools_cfg = cfg.get("offensive_tools", {})
    offensive_names = OFFENSIVE_TOOL_NAMES + tuple(
        str(n).lower() for n in tools_cfg.get("extra_names", [])
    )
    tunnel_names = TUNNEL_TOOL_NAMES + tuple(
        str(n).lower() for n in tools_cfg.get("extra_tunnel_names", [])
    )

    offensive_hits: dict[str, list[tuple[Event, dict, str]]] = {}
    tunnel_hits: dict[str, list[tuple[Event, dict, str]]] = {}
    for event in events:
        if event.event_type not in FS_EVENT_TYPES:
            continue
        fields = parse_fs_message(event.message)
        if fields is None or not fields.get("path"):
            continue
        path = fields["path"]
        tool = _match_tool(path, offensive_names)
        if tool is not None:
            offensive_hits.setdefault(tool, []).append((event, fields, path))
            continue
        tool = _match_tool(path, tunnel_names)
        if tool is not None:
            tunnel_hits.setdefault(tool, []).append((event, fields, path))

    findings: list[Finding] = []
    for category, hits, mitre_ids in (
        ("Offensive tooling", offensive_hits, ["T1588.002"]),
        ("Tunnel/proxy tooling", tunnel_hits, ["T1090"]),
    ):
        for tool, entries in sorted(hits.items()):
            paths = sorted({path for _ev, _fld, path in entries})
            any_exec = any(_executable(fld) for _ev, fld, _path in entries)
            severity = Severity.LOW if any_exec else Severity.INFO
            first_event = entries[0][0]
            refs = [Ref(ev.evidence_path, ev.line_or_offset) for ev, _f, _p in entries[:5]]
            findings.append(
                Finding(
                    id=make_finding_id(RULE, tool, paths[0]),
                    rule=RULE,
                    severity=severity,
                    title=f"{category} present: {tool} ({len(paths)} path(s))",
                    description=(
                        f"{len(paths)} triage path(s) match known {category.lower()} "
                        f"name {tool!r}: {', '.join(paths[:8])}"
                        + (f" (+{len(paths) - 8} more)" if len(paths) > 8 else "")
                        + ". Presence does not establish the operator: red-team "
                        "assessments and malicious use both leave these artifacts. "
                        + ("At least one match is executable."
                           if any_exec else "No match is executable (files/directories only).")
                    ),
                    mitre_ids=mitre_ids,
                    first_seen=first_event.timestamp_utc,
                    count=len(paths),
                    refs=refs,
                )
            )
    return findings
