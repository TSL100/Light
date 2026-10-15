# LinuxDFIR Toolkit

A read-only **Linux host collector** plus an offline **analyzer** for
authorized digital forensics and incident response. Collect evidence from a
suspected host with a single stdlib-only script, then verify, parse, detect,
and report on it from a separate workstation — no network calls at analysis
time.

> **Legal note.** Only collect from systems you are explicitly authorized to
> examine. Evidence routinely contains credentials, keys, and personal data;
> handle archives as confidential and run `linuxdfir scan-secrets` before
> sharing them.

## What's here

| Path | Purpose |
| --- | --- |
| `collector/linux_collector.py` | Single-file, stdlib-only Python collector |
| `collector/linux_collector.sh` | Bash fallback, same manifest schema |
| `linuxdfir/` | Analyzer package: verify, parse, detect, report |
| `linuxdfir/detection.toml` | Detection tuning (thresholds, allowlists) |
| `docs/` | DETECTIONS.md, EVIDENCE_FORMAT.md, REMOTE.md |
| `sample_evidence/generate.py` | Deterministic clean/infected fixtures |
| `tests/` | pytest suite (unit, detector, collector, e2e) |

## Installation (Windows analyzer host)

Python 3.11+ required.

```powershell
# in a virtual environment
pip install .
linuxdfir --version

# or with pipx, for an isolated CLI
pipx install .
```

For development extras (pytest, ruff):

```powershell
pip install .[dev]
```

Optional remote-collection helper (experimental, see `docs/REMOTE.md`):

```powershell
pip install .[remote]
```

### Standalone binary (optional)

For hosts where you cannot install Python, build a one-file executable with
PyInstaller. Optional and not exercised by CI.

A launcher script is needed because `linuxdfir.cli` is a package entry point:

```python
# launch.py
from linuxdfir.cli import main
raise SystemExit(main())
```

```powershell
pip install pyinstaller
pyinstaller --onefile --name linuxdfir --collect-data linuxdfir launch.py
.\dist\linuxdfir.exe --version
```

`--collect-data linuxdfir` is required so `detection.toml` ships inside the
bundle — without it the binary installs but cannot load detection config.
Expect a large binary (the stdlib is bundled). Only the *analyzer* is
packaged here; the collector is meant to run on the target.

## Collecting on Linux

Run the collector **as root** on the target so privileged artifacts are
reachable. It is read-only: targets are opened for reading and nothing on the
host is modified.

```bash
# whole running system
sudo python3 collector/linux_collector.py -o /safe/outside/evidence

# shorter runs
sudo python3 collector/linux_collector.py -o /safe/outside/evidence \
    --skip-live --skip-triage --tag case-4242
```

Notes:

- `-o` **must** point outside the evidence root; the collector refuses to
  write into what it is collecting.
- Output is `evidence.tar.gz` plus a `evidence.tar.gz.sha256` sidecar, and a
  manifest recorded inside the archive.
- Absent targets are logged to `collect.log` and to the manifest's `skipped[]`
  — nothing is silently dropped.
- `/mnt`, `/proc`, `/sys`, `/dev`, container and virtual mounts are pruned.
- Mounting and reading `evidence.tar.gz` elsewhere does not alter the target.

### No Python on the target?

Use the bash fallback. It needs `bash`, `python3`, `sha256sum`, and `stat`,
and emits the same manifest schema, so the analyzer accepts either archive
unchanged:

```bash
sudo bash collector/linux_collector.sh -o /safe/outside/evidence --tag case-4242
```

### From Windows, via WSL

```powershell
wsl.exe -e bash -c "sudo bash /mnt/c/path/to/collector/linux_collector.sh -o /mnt/c/path/to/out"
```

### Analyzing from another machine

Copy the archive (and sidecar) to your workstation, then continue below.
`linuxdfir verify` re-checks every hash against the manifest.

## Analyzer workflow

```powershell
# 1. integrity first: hashes, sidecar, missing/extra members
linuxdfir verify evidence.tar.gz

# 2. all four stages in one command: verify + parse + detect + report
linuxdfir run evidence.tar.gz -o case-out

# ...or run each stage separately
linuxdfir parse evidence.tar.gz -o case-out
linuxdfir detect case-out -o case-out
linuxdfir report case-out
```

`run` writes into the output directory:

| File | Contents |
| --- | --- |
| `verify_report.json` | Per-member integrity results |
| `events.jsonl` | Parsed, normalized timeline events |
| `findings.json` | Detector output with severity and MITRE refs |
| `timeline.db` / `timeline.csv` | SQLite + CSV timelines |
| `report.html` | Offline, self-contained report |
| `findings.csv` | Findings for spreadsheets/ticketing |

Open `report.html` in any browser — it needs no network access. Findings are
severity-tagged (critical → info), each with a count, MITRE ATT&CK references,
and pointers back to the source artifact (for example
`/var/log/auth.log:18`).

### Selecting parsers

```powershell
linuxdfir run evidence.tar.gz -o case-out --parsers auth_log,wtmp_btmp_lastlog,passwd_shadow_sudoers
```

`--parsers all` is the default. The registry is: `auditd`, `auth_log`,
`bash_history`, `cron`, `filesystem_suspicious`, `journald`, `ld_preload`,
`live_state`, `package_logs`, `passwd_shadow_sudoers`, `profile_scripts`,
`ssh`, `syslog_kern`, `systemd_units`, `web_logs`, `wtmp_btmp_lastlog`.
See `docs/EVIDENCE_FORMAT.md` for the artifacts each one consumes.

### Checking output before sharing

```powershell
linuxdfir scan-secrets case-out -o case-out
```

Scans collector output for accidental secret material and writes
`scan_secrets.json`.

## Configuring detections

Tune without touching code via a TOML file copied from
`linuxdfir/detection.toml`:

```powershell
linuxdfir run evidence.tar.gz -o case-out --config .\my-detection.toml
```

Useful knobs include package-install lookbacks, bulk-change thresholds, the
timestomp and offensive-tool rules, severity weights, and the risk-score
method. `docs/DETECTIONS.md` documents each detector, its thresholds, and
where to turn it down.

## Reading the risk score

Each host gets a 0–100 score derived from weighted findings with per-rule
decay and a saturation cap, so a flood of one low-severity signal cannot
single-handedly max out the score. Raw score, damped total, and the full
per-finding breakdown are recorded in `risk.json`. Treat the score as a
triage aid for ranking hosts, never as a verdict — read the findings.

## Limitations

- **Offline only.** No live response, no remote execution in the analyzer.
- **Point-in-time.** Evidence reflects the moment of collection; log rotation
  after collection is invisible.
- **Coverage depends on collection.** Artifacts not collected (for example
  `--skip-live`) produce no findings — absence of findings is not a clean bill
  of health.
- **Parser scope.** Parsers cover common artifacts (auth/wtmp/btmp/lastlog,
  shadow/passwd/group/sudoers, cron, systemd, package logs, webserver and SSH
  logs, shell history, `ld.so.preload`, kernel/audit logs, and triage
  listings). Custom formats need a new parser.
- **Windows-hosted analysis.** The analyzer targets Linux evidence but runs on
  Windows, macOS, or Linux.
- **Triage ceilings.** Recency/SUID/hidden/listing caps bound runtime and can
  truncate results on very large systems; the manifest records truncation.
- **Scores are heuristic.** Rules can misfire on unusual-but-legitimate
  environments; tune thresholds and allowlists rather than ignoring findings.
- **Not a sandbox.** Evidence files are parsed as data, but you are opening
  attacker-influenced content — analyze in an isolated environment.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `permission denied` / many `not_present` | Re-run the collector with `sudo`. |
| `output directory is inside evidence location` | Choose `-o` outside the collected root. |
| `integrity : FAILED` with `missing` members | Archive is truncated or was not copied completely; re-copy and re-verify. |
| `paramiko is required` | `pip install .[remote]`, or use manual SCP. |
| Bash collector: `python3 not found` | Install Python 3 on the target, or use the Python collector. |
| WSL: paths not found in tests | Tests locate the repo under `/mnt/c/...`; run them from the repo on a drive WSL can see. |
| Empty findings on an infected host | Confirm the relevant artifacts were collected (check `manifest.json` and `collect.log`). |
| Report won't open | It is a single self-contained HTML file; open it directly from disk. |

## Development

```powershell
pip install .[dev]
python -m pytest                # test suite
python -m ruff check .          # lint
```

See `docs/EVIDENCE_FORMAT.md` for the archive layout and manifest schema, and
`docs/DETECTIONS.md` for the detector catalogue.
