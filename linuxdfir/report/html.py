"""Single-file dark-themed HTML report (fully offline, no external requests).

Security model: every log-derived string (usernames, commands, paths, raw
lines) is attacker-controlled. Values rendered server-side go through
html.escape; values rendered client-side travel as escaped JSON and are
inserted with textContent only (the bundled script never uses innerHTML).
A restrictive Content-Security-Policy is emitted with hash pinning for the
inline style/script blocks (plus an 'unsafe-inline' fallback for older
viewers). Password hashes are redacted before rendering.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .. import __version__ as ANALYZER_VERSION
from ..detectors import RULE_INFO as DETECTOR_RULE_INFO
from ..ingest import RULE_INFO as INGEST_RULE_INFO
from ..mitre import TACTIC_ORDER, tactics_for, technique_name
from ..schema import Finding, Severity
from .sanitize import redact_shadow_hashes

CSS_TEXT = """*{box-sizing:border-box}
body{background:#0d1117;color:#e6edf3;font-family:-apple-system,'Segoe UI',Roboto,sans-serif;margin:0;
padding:0 16px 64px}
a{color:#58a6ff}
header.top{border-bottom:1px solid #30363d;padding:16px 0;margin-bottom:16px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:32px}
h3{font-size:14px;margin:18px 0 8px}
.meta{color:#8b949e;font-size:13px}
.meta b{color:#e6edf3}
.banner{border-radius:6px;padding:12px 16px;margin:16px 0;font-weight:600}
.banner.ok{background:#0f2c1c;border:1px solid #1f6f43;color:#7ee2a8}
.banner.bad{background:#3d1113;border:1px solid #b93a3e;color:#ffb4b8}
.banner.warn{background:#3a2a0c;border:1px solid #9a6a1a;color:#f0c674}
.grid{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}
.card{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;min-width:220px;flex:1}
.card .sev{font-size:12px;font-weight:700;padding:2px 8px;border-radius:10px;margin-right:8px}
.sev-critical{background:#7a1f22;color:#fff}
.sev-high{background:#9a4a12;color:#fff}
.sev-medium{background:#7a6512;color:#fff}
.sev-low{background:#1a4a7a;color:#fff}
.sev-info{background:#3a3f46;color:#fff}
.finding{background:#161b22;border:1px solid #30363d;border-left:4px solid #888;border-radius:6px;
padding:12px 16px;margin:12px 0}
.finding.sev-critical{border-left-color:#f85149}
.finding.sev-high{border-left-color:#f0883e}
.finding.sev-medium{border-left-color:#d29922}
.finding.sev-low{border-left-color:#58a6ff}
.finding.sev-info{border-left-color:#8b949e}
table{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0}
th,td{border:1px solid #30363d;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#1c2128;color:#8b949e}
tr.flash td{background:#3a2a0c}
code,pre,.mono{font-family:ui-monospace,'Cascadia Mono',Consolas,monospace;font-size:12px}
pre{background:#0a0d12;border:1px solid #30363d;border-radius:6px;padding:12px;overflow-x:auto;
white-space:pre-wrap;word-break:break-word}
.mitre-chip{display:inline-block;background:#1c2128;border:1px solid #58a6ff;border-radius:4px;
padding:2px 8px;margin:2px 4px 2px 0;font-size:12px}
.matrix{display:flex;gap:12px;flex-wrap:wrap}
.tactic{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 12px;min-width:200px;flex:1}
.tactic h4{margin:4px 0 8px;font-size:13px;color:#8b949e}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0;align-items:center}
.toolbar input,.toolbar select{background:#0a0d12;color:#e6edf3;border:1px solid #30363d;
border-radius:4px;padding:6px 8px}
.toolbar button{background:#1f6feb;color:#fff;border:none;border-radius:4px;padding:6px 12px;cursor:pointer}
details{margin:8px 0}
summary{cursor:pointer;color:#58a6ff}
.note{color:#8b949e;font-size:12px}
ul.tight{margin:6px 0;padding-left:20px}
ul.tight li{margin:2px 0}
.copy-btn{background:#1c2128;color:#8b949e;border:1px solid #30363d;border-radius:4px;
padding:2px 8px;cursor:pointer;font-size:11px}
.copy-btn:hover{color:#e6edf3;border-color:#58a6ff}
.risk-score{font-size:28px;font-weight:700}
ol.tight{margin:6px 0;padding-left:28px}
ol.tight li{margin:4px 0}"""

JS_TEXT = """(function(){
var timeline = JSON.parse(document.getElementById('timeline-data').textContent);
var tbody = document.getElementById('timeline-body');
var state = {q:'', artifact:'', user:'', ip:'', shown:500};
function norm(value){ return (value === null || value === undefined) ? '' : String(value); }
function match(row){
  if(state.artifact && row.art !== state.artifact){ return false; }
  if(state.user && row.user !== state.user){ return false; }
  var hay = norm(row.msg) + ' ' + norm(row.path) + ' ' + norm(row.user) + ' ' + norm(row.type);
  if(state.q && hay.toLowerCase().indexOf(state.q.toLowerCase()) < 0){ return false; }
  if(state.ip && hay.indexOf(state.ip) < 0){ return false; }
  return true;
}
function render(){
  while(tbody.firstChild){ tbody.removeChild(tbody.firstChild); }
  var shown = 0, matched = 0;
  for(var i = 0; i < timeline.rows.length; i++){
    var row = timeline.rows[i];
    if(!match(row)){ continue; }
    matched++;
    if(shown >= state.shown){ continue; }
    var tr = document.createElement('tr');
    var cells = [row.t, row.art, row.type, row.user, row.msg, row.path + ':' + row.line];
    for(var c = 0; c < cells.length; c++){
      var td = document.createElement('td');
      td.textContent = norm(cells[c]);
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
    shown++;
  }
  document.getElementById('timeline-count').textContent =
    'showing ' + shown + ' of ' + matched + ' matching rows (' + timeline.rows.length +
    ' embedded, ' + timeline.total + ' total)';
}
function fillSelect(id, values){
  var sel = document.getElementById(id);
  values.sort();
  for(var i = 0; i < values.length; i++){
    var opt = document.createElement('option');
    opt.textContent = values[i];
    opt.value = values[i];
    sel.appendChild(opt);
  }
}
(function init(){
  var arts = {}, users = {};
  for(var i = 0; i < timeline.rows.length; i++){ arts[timeline.rows[i].art] = 1; users[timeline.rows[i].user] = 1; }
  fillSelect('f-artifact', Object.keys(arts));
  fillSelect('f-user', Object.keys(users));
  document.getElementById('f-q').addEventListener('input', function(e){
    state.q = e.target.value; state.shown = 500; render();
  });
  document.getElementById('f-ip').addEventListener('input', function(e){
    state.ip = e.target.value; state.shown = 500; render();
  });
  document.getElementById('f-artifact').addEventListener('change', function(e){
    state.artifact = e.target.value; state.shown = 500; render();
  });
  document.getElementById('f-user').addEventListener('change', function(e){
    state.user = e.target.value; state.shown = 500; render();
  });
  document.getElementById('f-more').addEventListener('click', function(){ state.shown += 500; render(); });
  document.getElementById('f-sev').addEventListener('change', function(e){
    var cards = document.querySelectorAll('.finding');
    for(var i = 0; i < cards.length; i++){
      cards[i].style.display = (!e.target.value || cards[i].getAttribute('data-sev') === e.target.value) ? '' : 'none';
    }
  });
  var links = document.querySelectorAll('.ctx-link');
  for(var j = 0; j < links.length; j++){
    links[j].addEventListener('click', function(e){
      var table = document.getElementById(e.target.getAttribute('data-target'));
      if(!table){ return; }
      table.open = true;
      var rows = table.querySelectorAll('tr[data-path]');
      for(var k = 0; k < rows.length; k++){
        var hit = rows[k].getAttribute('data-path') === e.target.getAttribute('data-path')
          && rows[k].getAttribute('data-line') === e.target.getAttribute('data-line');
        rows[k].className = hit ? 'flash' : '';
      }
    });
  }
  document.addEventListener('click', function(e){
    var btn = e.target;
    if(!btn || !btn.classList || !btn.classList.contains('copy-btn')){ return; }
    var text = btn.getAttribute('data-copy') || '';
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text);
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch(err) {}
      document.body.removeChild(ta);
    }
    var prev = btn.textContent;
    btn.textContent = 'copied';
    setTimeout(function(){ btn.textContent = prev; }, 1200);
  });
  render();
})();
})();"""

HEAD_EVENTS = 2000
WINDOW_MINUTES = 15
WINDOW_CAP = 300

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

RULE_GUIDANCE = dict(DETECTOR_RULE_INFO)
RULE_GUIDANCE.update(INGEST_RULE_INFO)

FALLBACK_GUIDANCE = {
    "why": "No analyst guidance is registered for this rule yet.",
    "next_steps": ["Review the referenced evidence and correlate with the timeline."],
}


def _b64_sha256(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _json_blob(data) -> str:
    return json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")


def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _ref_key(path, line) -> tuple:
    return (path or "", "" if line is None else str(line))


def _parse_ts(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def collect_context(findings: list[Finding], events_path: Path) -> dict:
    ref_keys = set()
    windows: dict[str, list] = {}
    for finding in findings:
        for ref in finding.refs:
            ref_keys.add(_ref_key(ref.evidence_path, ref.line_or_offset))
        if finding.first_seen is not None or finding.last_seen is not None:
            start = finding.first_seen or finding.last_seen
            end = finding.last_seen or finding.first_seen
            delta = timedelta(minutes=WINDOW_MINUTES)
            windows[finding.id] = [start - delta, end + delta, 0]
    head: list[dict] = []
    ref_events: dict[tuple, dict] = {}
    window_events: dict[str, list] = {fid: [] for fid in windows}
    total = 0
    try:
        handle = open(events_path, encoding="utf-8")
    except OSError:
        return {"head": [], "ref_events": {}, "windows": {}, "total": 0, "truncated": True}
    with handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            if len(head) < HEAD_EVENTS:
                head.append(record)
            key = _ref_key(record.get("evidence_path"), record.get("line_or_offset"))
            if key in ref_keys and key not in ref_events:
                ref_events[key] = record
            stamp = _parse_ts(record.get("timestamp_utc"))
            if stamp is not None:
                for fid, (start, end, count) in windows.items():
                    if count < WINDOW_CAP and start <= stamp <= end:
                        window_events[fid].append(record)
                        windows[fid][2] += 1
    return {"head": head, "ref_events": ref_events, "windows": window_events, "total": total, "truncated": False}


def _slim_row(record: dict) -> dict:
    return {
        "t": record.get("timestamp_utc") or "",
        "q": record.get("timestamp_quality") or "",
        "host": record.get("host") or "",
        "user": redact_shadow_hashes(record.get("user")) or "",
        "art": record.get("source_artifact") or "",
        "type": record.get("event_type") or "",
        "msg": redact_shadow_hashes(record.get("message")) or "",
        "path": record.get("evidence_path") or "",
        "line": "" if record.get("line_or_offset") is None else str(record.get("line_or_offset")),
    }


def _finding_card(finding: Finding, ref_events: dict, window_events: list) -> str:
    guidance = RULE_GUIDANCE.get(finding.rule, FALLBACK_GUIDANCE)
    sev = finding.severity.value
    parts = [f'<div class="finding sev-{sev}" data-sev="{sev}">']
    parts.append(f'<div><span class="sev sev-{sev}">{esc(sev.upper())}</span><b>{esc(finding.title)}</b></div>')
    parts.append(f'<div class="meta">rule <span class="mono">{esc(finding.rule)}</span> · id {esc(finding.id)}')
    if finding.count != 1:
        parts.append(f" · count {finding.count}")
    if finding.first_seen is not None:
        parts.append(f" · first {esc(finding.first_seen.isoformat())}")
    if finding.last_seen is not None:
        parts.append(f" · last {esc(finding.last_seen.isoformat())}")
    parts.append("</div>")
    parts.append(f"<p>{esc(finding.description)}</p>")
    parts.append(f"<p><b>Why it matters:</b> {esc(guidance['why'])}</p>")
    if finding.mitre_ids:
        chips = []
        for mid in finding.mitre_ids:
            chips.append(f'<span class="mitre-chip">{esc(mid)} · {esc(technique_name(mid))}</span>')
        parts.append(f"<div>{''.join(chips)}</div>")
    parts.append("<p><b>Recommended next steps:</b></p><ul class='tight'>")
    for step in guidance["next_steps"]:
        parts.append(f"<li>{esc(step)}</li>")
    parts.append("</ul>")
    parts.append("<h3>Evidence</h3>")
    if finding.refs:
        parts.append(
            '<table><tr><th>Original path</th><th>Line/offset</th><th>Time (UTC)</th><th>Raw line</th><th></th></tr>'
        )
        for ref in finding.refs:
            record = ref_events.get(_ref_key(ref.evidence_path, ref.line_or_offset))
            stamp = esc(record.get("timestamp_utc")) if record and record.get("timestamp_utc") else "—"
            if ref.evidence_path == "manifest.json":
                raw = "<i>manifest reference, see appendix</i>"
            elif record is not None:
                raw = f"<code>{esc(redact_shadow_hashes(record.get('raw') or record.get('message') or ''))}</code>"
            else:
                raw = "<i>event not embedded</i>"
            line = esc(ref.line_or_offset) if ref.line_or_offset is not None else "—"
            link = (
                f'<a class="ctx-link" href="#ctx-{esc(finding.id)}" data-target="ctxbody-{esc(finding.id)}" '
                f'data-path="{esc(ref.evidence_path)}" data-line="{esc(ref.line_or_offset)}">context</a>'
            )
            parts.append(
                f"<tr><td class='mono'>{esc(ref.evidence_path)}</td><td>{line}</td><td class='mono'>{stamp}</td>"
                f"<td>{raw}</td><td>{link}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<p class='note'>No references recorded for this finding.</p>")
    if window_events:
        parts.append(
            f"<details id='ctx-{esc(finding.id)}'><summary>Surrounding timeline "
            f"({len(window_events)} events ±{WINDOW_MINUTES} min)</summary>"
            f"<table id='ctxbody-{esc(finding.id)}'>"
            "<tr><th>Time (UTC)</th><th>Artifact</th><th>Type</th><th>User</th><th>Message</th><th>Path:line</th></tr>"
        )
        for record in window_events:
            where = f"{record.get('evidence_path')}:{record.get('line_or_offset')}"
            parts.append(
                f"<tr data-path=\"{esc(record.get('evidence_path'))}\" "
                f"data-line=\"{esc(record.get('line_or_offset'))}\">"
                f"<td class='mono'>{esc(record.get('timestamp_utc'))}</td>"
                f"<td>{esc(record.get('source_artifact'))}</td><td>{esc(record.get('event_type'))}</td>"
                f"<td>{esc(record.get('user'))}</td><td>{esc(redact_shadow_hashes(record.get('message')))}</td>"
                f"<td class='mono'>{esc(where)}</td></tr>"
            )
        parts.append("</table></details>")
    parts.append("</div>")
    return "".join(parts)


def _matrix_section(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    severities: dict[str, Severity] = {}
    for finding in findings:
        for mid in finding.mitre_ids:
            counts[mid] = counts.get(mid, 0) + 1
            current = severities.get(mid)
            if current is None or SEVERITY_ORDER.index(finding.severity) > SEVERITY_ORDER.index(current):
                severities[mid] = finding.severity
    if not counts:
        return "<p class='note'>No MITRE ATT&amp;CK mappings in these findings.</p>"
    tactic_ids = [tid for tid, _ in TACTIC_ORDER]
    by_tactic: dict[str, list[str]] = {tid: [] for tid in tactic_ids}
    unmapped: list[str] = []
    for mid in sorted(counts):
        tactics = tactics_for(mid)
        if tactics:
            for tactic in tactics:
                by_tactic.setdefault(tactic, []).append(mid)
        else:
            unmapped.append(mid)
    parts = ['<div class="matrix">']
    for tid, tname in TACTIC_ORDER:
        techniques = sorted(set(by_tactic.get(tid, [])))
        if not techniques:
            continue
        parts.append(f"<div class='tactic'><h4>{esc(tid)} · {esc(tname)}</h4>")
        for tech in techniques:
            sev = severities[tech].value
            parts.append(
                f"<div><span class='mitre-chip'>{esc(tech)} · {esc(technique_name(tech))}</span> "
                f"<span class='meta'>×{counts[tech]} · {esc(sev)}</span></div>"
            )
        parts.append("</div>")
    if unmapped:
        parts.append("<div class='tactic'><h4>Unmapped technique IDs</h4>")
        for tech in sorted(unmapped):
            parts.append(f"<div><span class='mitre-chip'>{esc(tech)} · {esc(technique_name(tech))}</span></div>")
        parts.append("</div>")
    parts.append("</div>")
    return "".join(parts)


def _finding_sort_key(finding: Finding) -> tuple:
    first = finding.first_seen if finding.first_seen is not None else datetime.min.replace(tzinfo=UTC)
    return (SEVERITY_ORDER.index(finding.severity), finding.rule, first)


IOC_TABLE_CAP = 200

NOT_ANALYZED_STATIC = (
    "Memory dump / hibernation image — not collected; the process list is a live snapshot, not RAM.",
    "Full disk image — only selected artifacts were collected; unallocated space is unavailable.",
    "Packet capture / netflow — no network traffic evidence in this archive.",
    "Browser artifacts, mail stores, editor swap files — not collected.",
    "Cloud provider / EDR telemetry — outside the collector's scope.",
)


def _risk_section(risk: dict) -> str:
    hosts = risk.get("hosts") or {}
    if not hosts:
        return "<p class='note'>No risk score computed (run detect with an output directory).</p>"
    parts = ['<div class="grid">']
    for host_name, data in hosts.items():
        raw = data.get("raw_score", 0)
        score = data.get("score", 0)
        cap = data.get("cap", 0)
        parts.append(
            f"<div class='card'><b>{esc(host_name)}</b><br>"
            f"<span class='risk-score'>{esc(score)}</span>"
            f" <span class='meta'>/ {esc(cap)} cap (raw sum {esc(raw)})</span>"
        )
        by_sev = data.get("by_severity") or {}
        if by_sev:
            detail = " · ".join(f"{sev}×{count}" for sev, count in sorted(by_sev.items()))
            parts.append(f"<div class='meta'>{esc(detail)}</div>")
        parts.append("</div>")
    parts.append("</div>")
    method = risk.get("method")
    if method:
        parts.append(f"<p class='note'>Method: {esc(method)}</p>")
    users = risk.get("users") or {}
    if users:
        parts.append("<h3>Per-user scores</h3><table>")
        parts.append("<tr><th>User</th><th>Score</th><th>Findings</th><th>Contributing rules</th></tr>")
        for user in sorted(users, key=lambda name: -users[name].get("score", 0)):
            row = users[user]
            rules = sorted({item.get("rule", "") for item in row.get("breakdown", [])})
            parts.append(
                f"<tr><td class='mono'>{esc(user)}</td><td>{esc(row.get('score'))}</td>"
                f"<td>{esc(row.get('findings'))}</td>"
                f"<td class='mono'>{esc(', '.join(rules))}</td></tr>"
            )
        parts.append("</table>")
    breakdown = []
    for data in hosts.values():
        breakdown.extend(data.get("breakdown") or [])
    if breakdown:
        parts.append("<h3>Score breakdown</h3><table>")
        parts.append("<tr><th>Weight</th><th>Severity</th><th>Rule</th><th>Finding</th></tr>")
        for row in breakdown:
            sev = row.get("severity", "")
            parts.append(
                f"<tr><td>{esc(row.get('weight'))}</td>"
                f"<td><span class='sev sev-{esc(sev)}'>{esc(str(sev).upper())}</span></td>"
                f"<td class='mono'>{esc(row.get('rule'))}</td><td>{esc(row.get('title'))}</td></tr>"
            )
        parts.append("</table>")
    return "".join(parts)


def _narrative_section(correlation: dict) -> str:
    chains = correlation.get("chains") or []
    coverage = correlation.get("tactic_coverage") or []
    if not chains and not coverage:
        return (
            "<p class='note'>No multi-finding attack chain met the correlation "
            "threshold and no findings carry MITRE mappings.</p>"
        )
    parts = []
    if not chains:
        parts.append(
            "<p class='note'>No chain of two or more findings linked by a shared "
            "IP, path or rare username was found.</p>"
        )
    for chain in chains:
        confidence = chain.get("confidence", 0)
        label = chain.get("confidence_label", "low")
        parts.append(
            f"<h3>Chain <span class='mono'>{esc(chain.get('id'))}</span> — "
            f"{esc(label)} confidence ({esc(confidence)})</h3>"
        )
        parts.append(f"<p>{esc(chain.get('narrative', ''))}</p>")
        parts.append("<ol class='tight'>")
        for step in chain.get("steps", []):
            sev = step.get("severity", "info")
            when = step.get("first_seen") or "undated"
            parts.append(
                f"<li><span class='sev sev-{esc(sev)}'>{esc(str(sev).upper())}</span> "
                f"<b>{esc(step.get('title'))}</b> "
                f"<span class='meta mono'>{esc(step.get('rule'))} · {esc(when)}</span></li>"
            )
        parts.append("</ol>")
        tactic_names = chain.get("tactic_names") or []
        if tactic_names:
            chips = "".join(f"<span class='mitre-chip'>{esc(name)}</span>" for name in tactic_names)
            parts.append(f"<div>{chips}</div>")
    if coverage:
        parts.append("<h3>Tactic coverage</h3><table>")
        parts.append("<tr><th>Tactic</th><th>Findings</th><th>Rules</th></tr>")
        for row in coverage:
            parts.append(
                f"<tr><td>{esc(row.get('tactic_id'))} · {esc(row.get('name'))}</td>"
                f"<td>{esc(row.get('finding_count'))}</td>"
                f"<td class='mono'>{esc(', '.join(row.get('rules') or []))}</td></tr>"
            )
        parts.append("</table>")
    return "".join(parts)


def _ioc_section(iocs_data: dict) -> str:
    external = iocs_data.get("external") or []
    internal = iocs_data.get("internal") or []
    if not external and not internal:
        return "<p class='note'>No indicators extracted from events or findings.</p>"
    parts = []
    for label, rows in (("External", external), ("Internal / local", internal)):
        if not rows:
            continue
        parts.append(f"<h3>{label} indicators ({len(rows)})</h3>")
        parts.append(
            "<table><tr><th>Type</th><th>Indicator (defanged)</th><th>Sources</th><th></th></tr>"
        )
        for row in rows[:IOC_TABLE_CAP]:
            sources = row.get("sources") or []
            shown = ", ".join(sources[:4])
            extra = f" (+{len(sources) - 4} more)" if len(sources) > 4 else ""
            defanged = row.get("defanged", row.get("value", ""))
            parts.append(
                f"<tr><td>{esc(row.get('type'))}</td>"
                f"<td class='mono'>{esc(defanged)}</td>"
                f"<td class='mono'>{esc(shown)}{esc(extra)}</td>"
                f"<td><button type='button' class='copy-btn' "
                f"data-copy=\"{esc(defanged)}\">copy</button></td></tr>"
            )
        parts.append("</table>")
        if len(rows) > IOC_TABLE_CAP:
            parts.append(
                f"<p class='note'>Showing first {IOC_TABLE_CAP} of {len(rows)}; "
                "full list in iocs.json.</p>"
            )
    return "".join(parts)


def _not_analyzed_section(manifest, tl_stats) -> str:
    parts = [
        "<p class='note'>Absence of evidence in this archive is not evidence of "
        "absence on the host. The following were not analyzed or not present:</p>",
        "<ul class='tight'>",
    ]
    skipped = (manifest or {}).get("skipped") or []
    if skipped:
        parts.append(
            f"<li>{len(skipped)} collected artifact(s) were skipped during parse "
            "— see the appendix for the list.</li>"
        )
    undated = tl_stats.get("undated", 0)
    if undated:
        parts.append(
            f"<li>{esc(undated)} event(s) have no usable timestamp and sit "
            "outside time-ordered correlation.</li>"
        )
    for item in NOT_ANALYZED_STATIC:
        parts.append(f"<li>{esc(item)}</li>")
    parts.append("</ul>")
    return "".join(parts)


def build_report(out_dir: str | Path, *, report_name: str = "report.html") -> Path:
    out = Path(out_dir)
    findings = [Finding.from_dict(item) for item in _load_json(out / "findings.json", [])]
    ordered = sorted(findings, key=_finding_sort_key)
    manifest = _load_json(out / "manifest.json", None)
    verify = _load_json(out / "verify_report.json", None)
    tl_stats = _load_json(out / "timeline_stats.json", {})
    parse_stats = _load_json(out / "parse_stats.json", [])
    risk = _load_json(out / "risk.json", {})
    correlation = _load_json(out / "correlation.json", {})
    iocs_data = _load_json(out / "iocs.json", {"external": [], "internal": []})
    context = collect_context(findings, out / "events.jsonl")
    rows = [_slim_row(record) for record in context["head"]]

    by_sev: dict[str, int] = {}
    for finding in findings:
        by_sev[finding.severity.value] = by_sev.get(finding.severity.value, 0) + 1

    integrity_banner = '<div class="banner warn">Evidence integrity was not verified for this report.</div>'
    archive_sha = "unknown (no verify report)"
    if verify is not None:
        if verify.get("integrity_ok"):
            integrity_banner = '<div class="banner ok">Evidence integrity: OK — all manifest hashes verified.</div>'
        else:
            counts = verify.get("counts", {})
            integrity_banner = (
                '<div class="banner bad">Evidence integrity: FAILED — '
                f"mismatch {counts.get('mismatch', '?')}, missing {counts.get('missing', '?')}, "
                f"extra {counts.get('extra', '?')}</div>"
            )
        sidecar = (verify.get("sidecar") or {})
        if sidecar.get("actual"):
            archive_sha = sidecar["actual"]

    host = "unknown"
    collected = "unknown"
    host_tz = "unknown"
    environment = "unknown"
    collector_version = "unknown"
    if manifest:
        host = manifest.get("hostname") or "unknown"
        collected = manifest.get("collection_time_utc") or "unknown"
        tz = manifest.get("timezone") or {}
        host_tz = f"{tz.get('name') or '?'} (UTC{tz.get('utc_offset_str') or '?'})"
        env = manifest.get("environment") or {}
        environment = f"wsl={env.get('wsl')} container={env.get('container')} platform={env.get('platform')}"
        collector_version = ((manifest.get("collector") or {}).get("version")) or "unknown"

    days = sorted((tl_stats.get("per_day") or {}).keys())
    time_range = f"{days[0]} → {days[-1]}" if days else "no dated events"

    sections = []
    sections.append("<header class='top'><h1>LinuxDFIR Findings Report</h1>")
    sections.append(
        f"<div class='meta'>Host <b>{esc(host)}</b> · collected (UTC) <b>{esc(collected)}</b> · "
        f"host TZ <b>{esc(host_tz)}</b><br>Environment <b>{esc(environment)}</b><br>"
        f"Analyzer <b>linuxdfir {esc(ANALYZER_VERSION)}</b> · collector <b>{esc(collector_version)}</b><br>"
        f"Archive SHA256 <span class='mono'><b>{esc(archive_sha)}</b></span></div></header>"
    )
    sections.append(integrity_banner)
    sections.append("<h2>Executive summary</h2>")
    real_count = sum(count for sev, count in by_sev.items() if sev != Severity.INFO.value)
    info_count = by_sev.get(Severity.INFO.value, 0)
    sections.append(
        f"<div class='meta'><b>{real_count} actionable findings</b> + "
        f"{info_count} informational notes</div><div class='grid'>"
    )
    for sev in SEVERITY_ORDER:
        sections.append(
            f"<div class='card'><span class='sev sev-{sev.value}'>{esc(sev.value.upper())}</span>"
            f"<b style='font-size:20px'>{by_sev.get(sev.value, 0)}</b></div>"
        )
    sections.append(
        f"<div class='card'>Events<br><b style='font-size:20px'>{esc(tl_stats.get('total', '?'))}</b>"
        f"<div class='meta'>{esc(time_range)}</div></div>"
    )
    sections.append("</div>")
    if ordered:
        sections.append("<h3>Top findings</h3><ul class='tight'>")
        for finding in ordered[:3]:
            sections.append(f"<li><b>[{esc(finding.severity.value.upper())}]</b> {esc(finding.title)}</li>")
        sections.append("</ul>")

    sections.append("<h2>Risk score</h2>")
    sections.append(_risk_section(risk))

    sections.append("<h2>Attack narrative</h2>")
    sections.append(_narrative_section(correlation))

    sections.append(
        "<h2>Findings by severity</h2><div class='toolbar'><label>Severity <select id='f-sev'>"
        "<option value=''>all</option>"
        + "".join(f"<option value='{sev.value}'>{sev.value}</option>" for sev in SEVERITY_ORDER)
        + "</select></label></div>"
    )
    if ordered:
        for finding in ordered:
            sections.append(
                _finding_card(
                    finding,
                    context["ref_events"],
                    [item for item in context["windows"].get(finding.id, [])],
                )
            )
    else:
        sections.append("<p class='note'>No findings.</p>")

    sections.append("<h2>MITRE ATT&amp;CK matrix</h2>")
    sections.append(_matrix_section(findings))

    sections.append("<h2>Timeline</h2>")
    sections.append(
        f"<p class='note'>Embedded {len(rows)} of {context['total']} events "
        f"(plus per-finding context windows). Full data: <span class='mono'>timeline.csv</span>.</p>"
        "<div class='toolbar'>"
        "<label>Search <input id='f-q' type='text' placeholder='text, path, message'></label>"
        "<label>IP <input id='f-ip' type='text' placeholder='203.0.113.9'></label>"
        "<label>Artifact <select id='f-artifact'><option value=''>all</option></select></label>"
        "<label>User <select id='f-user'><option value=''>all</option></select></label>"
        "<button id='f-more' type='button'>Show more</button>"
        "</div>"
        "<div class='meta' id='timeline-count'></div>"
        "<table><thead><tr><th>Time (UTC)</th><th>Artifact</th><th>Type</th><th>User</th>"
        "<th>Message</th><th>Path:line</th></tr></thead><tbody id='timeline-body'></tbody></table>"
    )

    sections.append("<h2>Indicators of compromise</h2>")
    sections.append(_ioc_section(iocs_data))

    sections.append("<h2>What was not analyzed</h2>")
    sections.append(_not_analyzed_section(manifest, tl_stats))

    sections.append("<h2>Appendix</h2>")
    if verify is not None:
        sections.append("<h3>Verify report</h3><pre>" + esc(json.dumps(verify, indent=2)) + "</pre>")
    else:
        sections.append("<p class='note'>No verify report available.</p>")
    if parse_stats:
        sections.append("<h3>Parser stats</h3><pre>" + esc(json.dumps(parse_stats, indent=2)) + "</pre>")
    skipped = (manifest or {}).get("skipped", [])
    if skipped:
        sections.append("<h3>Skipped / not-present artifacts</h3><table>")
        sections.append("<tr><th>Path</th><th>Category</th><th>Status</th><th>Reason</th></tr>")
        for item in skipped:
            sections.append(
                f"<tr><td class='mono'>{esc(item.get('original_path'))}</td>"
                f"<td>{esc(item.get('category'))}</td><td>{esc(item.get('status'))}</td>"
                f"<td>{esc(item.get('reason'))}</td></tr>"
            )
        sections.append("</table>")
    elif manifest is not None:
        sections.append("<p class='note'>No skipped artifacts recorded.</p>")
    else:
        sections.append("<p class='note'>No manifest available; skipped artifacts unknown.</p>")

    generated = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    sections.append(
        f"<p class='note'>Generated {esc(generated)} by linuxdfir {esc(ANALYZER_VERSION)} (offline report).</p>"
    )

    style_hash = _b64_sha256(CSS_TEXT)
    script_hash = _b64_sha256(JS_TEXT)
    csp = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; "
        f"img-src 'none'; connect-src 'none'; style-src 'sha256-{style_hash}' 'unsafe-inline'; "
        f"script-src 'sha256-{script_hash}' 'unsafe-inline'"
    )
    page = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<meta http-equiv='Content-Security-Policy' content='{csp}'>"
        f"<title>LinuxDFIR report · {esc(host)}</title>"
        f"<style>{CSS_TEXT}</style></head><body>"
        + "".join(sections)
        + "<script type='application/json' id='timeline-data'>"
        + f"{_json_blob({'rows': rows, 'total': context['total']})}</script>"
        + f"<script>{JS_TEXT}</script></body></html>"
    )
    target = out / report_name
    target.write_text(page, encoding="utf-8")
    return target
