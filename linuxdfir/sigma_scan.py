"""Optional Sigma-rule matching over normalized events.

Sigma rules are *optional* input (``pip install linuxdfir[sigma]`` for the
YAML parser). Everything here lazy-imports ``yaml`` so the core pipeline
never requires it: when PyYAML is missing the scan is skipped cleanly with
``status: skipped`` instead of raising.

Only a documented subset of Sigma is evaluated, restricted to Linux
log sources relevant to this toolkit:

* ``logsource`` must carry ``product: linux`` **and** either
  ``category: process_creation`` or ``service`` in
  ``{auth, syslog, auditd}``. Rules outside that subset are loaded but
  skipped (counted in stats, never silently dropped).
* ``detection`` supports named selections plus a ``condition`` using
  ``and`` / ``or`` / ``not``, parentheses, ``1 of X*`` and ``all of X*``.
* Selection values support exact match and the ``contains``,
  ``startswith``, ``endswith`` and ``re`` modifiers (plus ``all`` for
  list semantics). String comparison is case-insensitive except ``re``.

Sigma field names are mapped onto the Event schema (see ``FIELD_MAP``);
unknown fields are a load-time error, never a silent non-match.

Each Sigma rule that matches at least one event becomes one ``sigma_match``
Finding: the title names the Sigma rule (and its id), refs point at the
matched events, severity comes from the Sigma ``level`` (else the
``[sigma]`` default), and ``attack.tXXXX`` tags become MITRE IDs.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .config import load_config
from .schema import Event, Finding, Ref, Severity, make_finding_id, parse_severity

RULE = "sigma_match"

RULE_INFO = {
    RULE: {
        "why": (
            "A Sigma rule written for Linux auth, syslog, auditd or process "
            "creation matched normalized events from this host. Sigma rules "
            "encode community detection logic, so a match is a strong pivot: "
            "confirm the underlying events and hunt the same pattern fleet-wide."
        ),
        "next_steps": [
            "Read the matched events behind the finding (refs) and confirm they show the ruled behaviour.",
            "Check the Sigma rule's references/falsepositives fields for known-benign triggers.",
            "Hunt the same Sigma rule across the rest of the fleet's events.",
            "Tune [sigma] severity in detection.toml if the rule is noisy in your environment.",
        ],
    },
}

RULE_EXTENSIONS = (".yml", ".yaml")
DEFAULT_SEVERITY = Severity.MEDIUM

SUPPORTED_CATEGORIES = {"process_creation"}
SUPPORTED_SERVICES = {"auth", "syslog", "auditd"}

# Sigma field name (lowercased, spaces/underscores stripped) -> Event attribute.
FIELD_MAP = {
    "user": "user",
    "username": "user",
    "account": "user",
    "targetuser": "user",
    "targetusername": "user",
    "host": "host",
    "hostname": "host",
    "computer": "host",
    "computername": "host",
    "commandline": "message",
    "command": "message",
    "processcommandline": "message",
    "message": "message",
    "raw": "raw",
    "eventtype": "event_type",
    "event_type": "event_type",
    "source": "source_artifact",
    "sourceartifact": "source_artifact",
    "source_artifact": "source_artifact",
    "evidencepath": "evidence_path",
    "evidence_path": "evidence_path",
    "path": "evidence_path",
    "filepath": "evidence_path",
    "parser": "parser",
    "image": "message",
    "process": "message",
    "processname": "message",
    "processpath": "message",
    "originalfilename": "message",
    "company": "message",
    "product": "message",
    "description": "message",
    "tags": "tags",
}

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}

LEVEL_SEVERITY = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_MITRE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_MAX_REFS = 5


class SigmaUnavailable(Exception):
    """Raised when PyYAML is not installed."""


def _import_yaml() -> Any:
    """Lazy-import yaml; never at module import time."""
    try:
        import yaml  # noqa: PLC0415
    except ImportError as exc:
        raise SigmaUnavailable(
            "PyYAML is not installed; skipping Sigma scan "
            "(install with: pip install linuxdfir[sigma])"
        ) from exc
    if getattr(yaml, "safe_load", None) is None:
        raise SigmaUnavailable("installed yaml module has no safe_load(); cannot scan")
    return yaml


def _rule_files(rules_dir: str | Path) -> list[Path]:
    root = Path(rules_dir)
    if not root.is_dir():
        raise ValueError(f"Sigma rules folder is not a directory: {root}")
    files = sorted(
        path for path in root.iterdir()
        if path.is_file() and path.suffix.lower() in RULE_EXTENSIONS
    )
    if not files:
        raise ValueError(f"no Sigma rules (*.yml/*.yaml) in: {root}")
    return files


def _logsource_ok(logsource: Any) -> tuple[bool, str]:
    """Check a rule's logsource against the supported Linux subset."""
    if not isinstance(logsource, dict):
        return False, "missing logsource mapping"
    product = str(logsource.get("product", "") or "").strip().lower()
    category = str(logsource.get("category", "") or "").strip().lower()
    service = str(logsource.get("service", "") or "").strip().lower()
    if product != "linux":
        return False, f"product {product!r} is not linux"
    if category in SUPPORTED_CATEGORIES or service in SUPPORTED_SERVICES:
        return True, ""
    return False, f"category {category!r}/service {service!r} outside auth/syslog/auditd/process_creation subset"


def _split_field_key(key: str) -> tuple[str, list[str]]:
    """Split 'Field|mod1|mod2' into (attribute, modifiers), validating both."""
    parts = [part.strip() for part in str(key).split("|")]
    name = re.sub(r"[\s_]+", "", parts[0]).lower()
    if name not in FIELD_MAP:
        raise ValueError(
            f"unsupported Sigma field {parts[0]!r} (supported: {sorted(set(FIELD_MAP))})"
        )
    modifiers = [mod.lower() for mod in parts[1:] if mod]
    for mod in modifiers:
        if mod not in SUPPORTED_MODIFIERS:
            raise ValueError(
                f"unsupported Sigma modifier {mod!r} (supported: {sorted(SUPPORTED_MODIFIERS)})"
            )
    return FIELD_MAP[name], modifiers


def _compile_value_test(attribute: str, modifiers: list[str], expected: Any) -> dict:
    """Compile one field expectation into a test dict (regexes precompiled)."""
    if isinstance(expected, str) and "re" in modifiers and expected is not None:
        try:
            compiled = re.compile(expected)
        except re.error as exc:
            raise ValueError(f"invalid regex for {attribute}: {expected!r}: {exc}") from exc
    else:
        compiled = None
    return {"attribute": attribute, "modifiers": modifiers, "expected": expected, "regex": compiled}


def _compile_selection(name: str, body: Any) -> dict:
    """Compile a named selection into AND-of-field-tests (OR across list items)."""
    if isinstance(body, dict):
        alternatives = [body]
    elif isinstance(body, list):
        if not body or not all(isinstance(item, dict) for item in body):
            raise ValueError(f"selection {name!r} must be a mapping or list of mappings")
        alternatives = body
    else:
        raise ValueError(f"selection {name!r} must be a mapping or list of mappings")
    compiled_alts = []
    for alt in alternatives:
        tests = []
        for key, expected in alt.items():
            attribute, modifiers = _split_field_key(key)
            if isinstance(expected, list):
                if "all" in modifiers:
                    for item in expected:
                        tests.append(_compile_value_test(attribute, modifiers, item))
                else:
                    tests.append(
                        {
                            "attribute": attribute,
                            "modifiers": modifiers,
                            "expected": expected,
                            "regex": None,
                            "any_of": True,
                        }
                    )
            else:
                tests.append(_compile_value_test(attribute, modifiers, expected))
        compiled_alts.append(tests)
    return {"name": name, "any_of_alternatives": compiled_alts}


# --- condition parsing: and/or/not, parens, "1 of X*" / "all of X*" --------

_COND_TOKEN_RE = re.compile(r"\(|\)|\b1 of\b|\ball of\b|\band\b|\bor\b|\bnot\b|[^\s()]+", re.IGNORECASE)


def _tokenize_condition(condition: str) -> list[str]:
    tokens = [tok for tok in _COND_TOKEN_RE.findall(condition) if tok.strip()]
    if not tokens:
        raise ValueError("empty Sigma condition")
    return tokens


def _parse_condition(tokens: list[str]) -> tuple[Any, list[str]]:
    node, rest = _parse_or(tokens)
    if rest:
        raise ValueError(f"unexpected trailing tokens in Sigma condition: {rest}")
    return node, rest


def _parse_or(tokens: list[str]) -> tuple[Any, list[str]]:
    left, tokens = _parse_and(tokens)
    parts = [left]
    while tokens and tokens[0].lower() == "or":
        right, tokens = _parse_and(tokens[1:])
        parts.append(right)
    return left if len(parts) == 1 else ("or", parts), tokens


def _parse_and(tokens: list[str]) -> tuple[Any, list[str]]:
    left, tokens = _parse_not(tokens)
    parts = [left]
    while tokens and tokens[0].lower() == "and":
        right, tokens = _parse_not(tokens[1:])
        parts.append(right)
    return left if len(parts) == 1 else ("and", parts), tokens


def _parse_not(tokens: list[str]) -> tuple[Any, list[str]]:
    if tokens and tokens[0].lower() == "not":
        operand, rest = _parse_not(tokens[1:])
        return ("not", operand), rest
    return _parse_primary(tokens)


def _parse_primary(tokens: list[str]) -> tuple[Any, list[str]]:
    if not tokens:
        raise ValueError("truncated Sigma condition")
    head = tokens[0].lower()
    if head == "(":
        node, rest = _parse_or(tokens[1:])
        if not rest or rest[0] != ")":
            raise ValueError("unbalanced parenthesis in Sigma condition")
        return node, rest[1:]
    if head in ("1 of", "all of"):
        if len(tokens) < 2:
            raise ValueError(f"truncated Sigma condition after {tokens[0]!r}")
        return (head, tokens[1]), tokens[2:]
    if head in ("and", "or", "not", ")"):
        raise ValueError(f"unexpected {tokens[0]!r} in Sigma condition")
    return ("ref", tokens[0]), tokens[1:]


def _resolve_refs(pattern: str, selections: dict) -> list[str]:
    """Resolve a selection reference (exact name or fnmatch pattern) to names."""
    if pattern in selections:
        return [pattern]
    matched = [name for name in selections if fnmatch.fnmatchcase(name, pattern)]
    if not matched:
        raise ValueError(f"Sigma condition references unknown selection {pattern!r}")
    return matched


def _eval_condition(node: Any, selections: dict, match_sel) -> bool:
    kind = node[0]
    if kind == "ref":
        for name in _resolve_refs(node[1], selections):
            if match_sel(name):
                return True
        return False
    if kind == "not":
        return not _eval_condition(node[1], selections, match_sel)
    if kind == "and":
        return all(_eval_condition(part, selections, match_sel) for part in node[1])
    if kind == "or":
        return any(_eval_condition(part, selections, match_sel) for part in node[1])
    if kind == "1 of":
        for name in _resolve_refs(node[1], selections):
            if match_sel(name):
                return True
        return False
    if kind == "all of":
        names = _resolve_refs(node[1], selections)
        return all(match_sel(name) for name in names)
    raise ValueError(f"invalid Sigma condition node: {node!r}")  # pragma: no cover - parser-owned


# --- event matching ----------------------------------------------------------


def _event_values(event: Event, attribute: str) -> list[str | None]:
    value = getattr(event, attribute, None)
    if value is None:
        return [None]
    if isinstance(value, list):
        return [None if item is None else str(item) for item in value]
    return [str(value)]


def _match_test(test: dict, event: Event) -> bool:
    """Match one compiled field test against an event."""
    actuals = _event_values(event, test["attribute"])
    modifiers = test["modifiers"]
    expected = test["expected"]
    if test.get("any_of"):
        return any(_match_single(a, modifiers, item, test["regex"]) for a in actuals for item in expected)
    return any(_match_single(a, modifiers, expected, test["regex"]) for a in actuals)


def _match_single(actual: str | None, modifiers: list[str], expected: Any, compiled: Any) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False
    if isinstance(expected, bool):
        return actual.strip().lower() == str(expected).lower()
    want = str(expected)
    if "re" in modifiers:
        try:
            return compiled.search(actual) is not None
        except Exception:
            return False
    hay, needle = actual.casefold(), want.casefold()
    if "contains" in modifiers:
        return needle in hay
    if "startswith" in modifiers:
        return hay.startswith(needle)
    if "endswith" in modifiers:
        return hay.endswith(needle)
    return hay == needle


def _selection_matches(compiled_sel: dict, event: Event) -> bool:
    return any(
        all(_match_test(test, event) for test in tests)
        for tests in compiled_sel["any_of_alternatives"]
    )


# --- rule loading ------------------------------------------------------------


def _mitre_from_tags(tags: Any) -> list[str]:
    mitre: list[str] = []
    if isinstance(tags, list):
        for tag in tags:
            match = _MITRE_TAG_RE.match(str(tag or "").strip())
            if match and match.group(1).upper() not in mitre:
                mitre.append(match.group(1).upper())
    return mitre


def _level_severity(level: Any, default: Severity) -> Severity:
    if isinstance(level, str) and level.strip():
        return LEVEL_SEVERITY.get(level.strip().lower(), default)
    return default


def _default_severity(config: dict | None) -> Severity:
    raw = (config or {}).get("sigma", {}).get("severity", DEFAULT_SEVERITY.value)
    try:
        return parse_severity(str(raw))
    except ValueError:
        return DEFAULT_SEVERITY


def load_rules(rules_dir: str | Path) -> tuple[list[dict], dict]:
    """Load and validate Sigma rules; out-of-subset rules are skipped, not errors.

    Returns ``(rules, info)``. ``info`` carries files loaded, per-file skip
    reasons and the logsource subset definition. Malformed YAML, missing
    ``detection``/``condition``, unknown fields or modifiers, and bad regexes
    raise ValueError naming the rule file. Missing PyYAML raises
    SigmaUnavailable.
    """
    yaml = _import_yaml()
    info: dict = {
        "rules_dir": str(Path(rules_dir)),
        "rules_files": [],
        "rules_loaded": 0,
        "rules_skipped_logsource": 0,
        "logsource_subset": {
            "product": "linux",
            "categories": sorted(SUPPORTED_CATEGORIES),
            "services": sorted(SUPPORTED_SERVICES),
        },
        "skipped": [],
    }
    rules: list[dict] = []
    for path in _rule_files(rules_dir):
        info["rules_files"].append(path.name)
        try:
            with open(path, encoding="utf-8") as handle:
                doc = yaml.safe_load(handle)
        except Exception as exc:
            raise ValueError(f"cannot parse Sigma rule {path.name}: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError(f"Sigma rule {path.name} must be a YAML mapping")
        title = str(doc.get("title") or path.stem)
        ok, reason = _logsource_ok(doc.get("logsource"))
        if not ok:
            info["rules_skipped_logsource"] += 1
            info["skipped"].append({"file": path.name, "title": title, "reason": reason})
            continue
        detection = doc.get("detection")
        if not isinstance(detection, dict) or not detection:
            raise ValueError(f"Sigma rule {path.name} needs a non-empty detection mapping")
        condition = detection.get("condition")
        if not isinstance(condition, str) or not condition.strip():
            raise ValueError(f"Sigma rule {path.name} needs a string detection.condition")
        selections = {}
        try:
            for name, body in detection.items():
                if name == "condition":
                    continue
                selections[str(name)] = _compile_selection(str(name), body)
            tokens = _tokenize_condition(condition)
            parsed, _ = _parse_condition(tokens)
        except ValueError as exc:
            raise ValueError(f"Sigma rule {path.name} ({title}): {exc}") from exc
        # Eagerly resolve condition references so typos fail at load, not per event.
        _check_refs(parsed, selections, path.name)
        rule_id = str(doc.get("id") or title)
        rules.append(
            {
                "id": rule_id,
                "title": title,
                "description": str(doc.get("description") or ""),
                "level": doc.get("level"),
                "tags": list(doc.get("tags") or []),
                "logsource": doc.get("logsource") or {},
                "selections": selections,
                "condition": parsed,
                "source_file": path.name,
            }
        )
        info["rules_loaded"] += 1
    return rules, info


def _check_refs(node: Any, selections: dict, filename: str) -> None:
    kind = node[0]
    if kind == "ref":
        _resolve_refs(node[1], selections)
    elif kind == "not":
        _check_refs(node[1], selections, filename)
    elif kind in ("and", "or"):
        for part in node[1]:
            _check_refs(part, selections, filename)
    elif kind in ("1 of", "all of"):
        _resolve_refs(node[1], selections)


def rule_matches(rule: dict, event: Event) -> bool:
    """Evaluate one compiled rule's condition against one event."""
    selections = rule["selections"]

    def match_sel(name: str) -> bool:
        return _selection_matches(selections[name], event)

    return _eval_condition(rule["condition"], selections, match_sel)


def scan_events(
    events: Iterable[Event],
    rules: list[dict],
    config: dict | None = None,
) -> tuple[list[Finding], dict]:
    """Match compiled rules against events; one Finding per matching rule."""
    default_severity = _default_severity(config)
    event_list = list(events)
    stats: dict = {"status": "ok", "events_scanned": len(event_list), "matches": 0, "total_hits": 0}
    findings: list[Finding] = []
    for rule in rules:
        hits: list[Event] = []
        for event in event_list:
            try:
                matched = rule_matches(rule, event)
            except Exception:
                continue
            if matched:
                hits.append(event)
        if not hits:
            continue
        stats["matches"] += 1
        stats["total_hits"] += len(hits)
        first = min((e.timestamp_utc for e in hits if e.timestamp_utc), default=None)
        last = max((e.timestamp_utc for e in hits if e.timestamp_utc), default=None)
        refs = [Ref(e.evidence_path, e.line_or_offset) for e in hits[:_MAX_REFS]]
        sample = "; ".join(e.message[:120] for e in hits[:3])
        logsource = rule.get("logsource") or {}
        findings.append(
            Finding(
                id=make_finding_id(RULE, rule["id"]),
                rule=RULE,
                severity=_level_severity(rule.get("level"), default_severity),
                title=f"Sigma match: {rule['title']} ({rule['id']})",
                description=(
                    f"Sigma rule {rule['title']!r} from {rule['source_file']} "
                    f"(logsource product={logsource.get('product')}, "
                    f"category={logsource.get('category')}, service={logsource.get('service')}) "
                    f"matched {len(hits)} event(s)"
                    + (f" (+{len(hits) - _MAX_REFS} more)" if len(hits) > _MAX_REFS else "")
                    + f". e.g. {sample}."
                    + (f" {rule['description']}" if rule.get("description") else "")
                ),
                mitre_ids=_mitre_from_tags(rule.get("tags")),
                first_seen=first,
                last_seen=last,
                count=len(hits),
                refs=refs,
            )
        )
    return findings, stats


def scan_with_rules_dir(
    events: Iterable[Event],
    rules_dir: str | Path,
    config: dict | None = None,
) -> tuple[list[Finding], dict]:
    """Load ``rules_dir`` and scan; missing PyYAML skips cleanly.

    Returns ``(findings, stats)``. When PyYAML is absent the findings list is
    empty and ``stats["status"] == "skipped"`` with a human-readable
    ``reason``. A bad rules folder or invalid rule raises ValueError.
    ``events`` may be any iterable; it is materialized once.
    """
    cfg = config if config is not None else load_config()
    try:
        rules, info = load_rules(rules_dir)
    except SigmaUnavailable as exc:
        return [], {
            "status": "skipped",
            "reason": str(exc),
            "rules_dir": str(Path(rules_dir)),
            "rules_files": [],
            "rules_loaded": 0,
            "rules_skipped_logsource": 0,
            "events_scanned": 0,
            "matches": 0,
            "total_hits": 0,
        }
    event_list = list(events)
    findings, scan_stats = scan_events(event_list, rules, cfg)
    return findings, {
        "status": "ok",
        "rules_dir": info["rules_dir"],
        "rules_files": info["rules_files"],
        "rules_loaded": info["rules_loaded"],
        "rules_skipped_logsource": info["rules_skipped_logsource"],
        "skipped": info["skipped"],
        "events_scanned": len(event_list),
        "matches": scan_stats["matches"],
        "total_hits": scan_stats["total_hits"],
    }
