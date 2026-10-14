"""Web attacks: webshell access, injection probes and scanner activity."""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlsplit

from ..parsers.web_logs import parse_web_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "webshell_and_web_attacks"

RULE_INFO = {
    RULE: {
        "why": (
            "Script files served from upload directories, command-execution "
            "parameters and injection probes that return 200 mean the web "
            "application is being exploited, often to drop a webshell."
        ),
        "next_steps": [
            "Take the hit URIs and isolate the webshell file; preserve it before cleanup.",
            "Check what the webshell executed (access log follow-ups, shell history, new processes).",
            "Patch or take offline the vulnerable upload/parameter handler.",
            "Block the source IP and hunt its other requests across all vhosts.",
        ],
    },
}

WEBSHELL_PATH_RE = re.compile(
    r"(?:uploads?|files|media|images|tmp|cache|static|wp-content/uploads)/[^\s?]*"
    r"\.(php\d?|phtml|phar|jsp|jspx|asp|aspx|cfm|pl|py|rb|sh)\b",
    re.IGNORECASE,
)
CMD_PARAM_RE = re.compile(
    r"[?&](cmd|command|exec|execute|code|q|shell|payload)=|\b(system|exec|shell_exec|passthru|popen|proc_open|eval|assert)\s*\(",
    re.IGNORECASE,
)
SQLI_RE = re.compile(
    r"('\s*(or|and)\s+1\s*=\s*1|union\s+select|information_schema|;\s*(drop|select)\s|--|/\*!)",
    re.IGNORECASE,
)
LFI_RE = re.compile(r"(\.\./|\.\.%2f|etc/passwd|etc/shadow|boot\.ini|win\.ini)", re.IGNORECASE)
RCE_RE = re.compile(r"(\$\{jndi:|\|\s*id\b|`id`|\$\(id\)|;\s*id\s*;)", re.IGNORECASE)
SCANNER_UA_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|dirb|nessus|nuclei|wpscan|hydra|medusa|acunetix|netsparker|burp)",
    re.IGNORECASE,
)
SCRIPT_EXT_RE = re.compile(r"\.(php\d?|phtml|phar|jsp|jspx|asp|aspx|cfm)\b", re.IGNORECASE)

SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("webshell-path", WEBSHELL_PATH_RE),
    ("cmd-exec", CMD_PARAM_RE),
    ("sqli", SQLI_RE),
    ("lfi", LFI_RE),
    ("rce", RCE_RE),
]

SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def _path(uri: str) -> str:
    return urlsplit(uri).path or uri.split("?", 1)[0]


def detect(events: Iterable[Event]) -> list[Finding]:
    requests: list[tuple[Event, dict]] = []
    for event in events:
        if event.event_type != "web_request":
            continue
        info = parse_web_message(event.message)
        if info is not None:
            requests.append((event, info))
    get_paths = {_path(info["uri"]) for _, info in requests if info["method"] == "GET"}
    findings: list[Finding] = []

    high_groups: dict[tuple, dict] = {}
    repeat_counts: dict[tuple, dict] = {}
    for event, info in requests:
        sigs = [name for name, pattern in SIGNATURES if pattern.search(info["uri"])]
        scanner = bool(SCANNER_UA_RE.search(info["ua"] or ""))
        success = 200 <= info["status"] < 300
        path = _path(info["uri"])
        if sigs and success:
            key = (info["ip"], path)
            group = high_groups.setdefault(key, {"events": [], "sigs": [], "statuses": []})
            group["events"].append(event)
            for sig in sigs:
                if sig not in group["sigs"]:
                    group["sigs"].append(sig)
            group["statuses"].append(info["status"])
        elif sigs or scanner:
            key = (info["ip"], sigs[0] if sigs else "scanner", path)
            group = repeat_counts.setdefault(key, {"events": [], "scanner": scanner, "success": False})
            group["events"].append(event)
    for (ip, path), group in sorted(high_groups.items(), key=lambda item: str(item[0])):
        findings.append(
            Finding(
                id=make_finding_id(RULE, "hit", ip, path),
                rule=RULE,
                severity=Severity.HIGH,
                title=f"Likely webshell/exploit hit from {ip}: {path}",
                description=(
                    f"{len(group['events'])} successful request(s) ({', '.join(map(str, group['statuses']))}) "
                    f"matching {', '.join(group['sigs'])}."
                ),
                mitre_ids=["T1190", "T1505.003"],
                count=len(group["events"]),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in group["events"]],
            )
        )
    for (ip, sig, path), group in sorted(repeat_counts.items(), key=lambda item: str(item[0])):
        if len(group["events"]) >= 3 or group["scanner"]:
            severity = Severity.MEDIUM
            title = f"Repeated web probing from {ip} ({sig})"
        else:
            severity = Severity.LOW
            title = f"Web attack signature from {ip} ({sig}): {path}"
        findings.append(
            Finding(
                id=make_finding_id(RULE, "probe", ip, sig, path),
                rule=RULE,
                severity=severity,
                title=title,
                description=f"{len(group['events'])} request(s) matching {sig}.",
                mitre_ids=["T1190"],
                count=len(group["events"]),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in group["events"]],
            )
        )
    post_groups: dict[tuple, list] = {}
    for event, info in requests:
        if info["method"] != "POST" or not 200 <= info["status"] < 300:
            continue
        path = _path(info["uri"])
        if path in get_paths or not SCRIPT_EXT_RE.search(path):
            continue
        post_groups.setdefault((info["ip"], path), []).append(event)
    for (ip, path), evts in sorted(post_groups.items(), key=lambda item: str(item[0])):
        findings.append(
            Finding(
                id=make_finding_id(RULE, "post-new", ip, path),
                rule=RULE,
                severity=Severity.MEDIUM,
                title=f"POST to never-fetched script from {ip}: {path}",
                description=(
                    f"{len(evts)} successful POST(s) to a script path with no prior GET: "
                    "possible webshell upload-then-execute."
                ),
                mitre_ids=["T1505.003"],
                count=len(evts),
                refs=[Ref(event.evidence_path, event.line_or_offset) for event in evts],
            )
        )
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.id))
    return findings
