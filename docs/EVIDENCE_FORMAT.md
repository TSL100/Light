# Evidence format

Both collectors (`collector/linux_collector.py` and the bash fallback
`collector/linux_collector.sh`) emit the **same archive layout and the same
manifest schema**, so the analyzer accepts either archive unchanged.

## Archive layout

```
evidence.tar.gz
├── manifest.json            collection record + integrity baseline
├── collect.log              every INFO/SKIP/NOT PRESENT line from the run
├── evidence/                collected files, mirroring absolute paths
│   ├── etc/passwd           ← /etc/passwd
│   ├── var/log/auth.log     ← /var/log/auth.log
│   └── root/.ssh/authorized_keys
├── live/                    live command output (skipped with --skip-live)
│   ├── ps_auxf.txt
│   ├── ss_tulpn.txt
│   └── ...
└── triage/                  filesystem triage listings (TSV, header first)
    ├── tmp_listing.txt
    ├── suid_sgid.txt
    └── recent_files.txt
```

Alongside the archive:

```
evidence.tar.gz          the archive
evidence.tar.gz.sha256   sidecar: "<sha256>  evidence.tar.gz"
```

`evidence/<path>` mirrors the target's absolute path with the leading `/`
removed, so `/var/log/auth.log` → `evidence/var/log/auth.log`. Paths that
cannot be copied (permission, type, absent) appear in the manifest with a
status and reason rather than as archive members.

### Pruned paths

Never walked: `/proc`, `/sys`, `/dev`, `/mnt`, `/run`, `/snap`,
`/lost+found`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/lxc`,
`/var/lib/kubelet`. Recorded as `triage_prunes` in the manifest.

### Live commands

`live/<name>.txt` for: `ps_auxf`, `ss_tulpn`, `lsof_nP`, `who`, `last`,
`lsmod`, `mount`, `df`, `docker_ps_a`, `iptables_save`, `ip6tables_save`,
`journalctl_export`, plus per-user `crontab_<user>` entries. Stdout and stderr
are separated by a `<<<STDERR>>>` line. Missing binaries are recorded as
`not_present` in `live_commands[]` and `skipped[]`, never dropped.

### Triage listings

TSV with a header line as row 1:

| File | Header |
| --- | --- |
| `tmp_listing.txt` | `path type mode uid gid size mtime_utc ctime_utc atime_utc` |
| `var_tmp_listing.txt` | same as above |
| `dev_shm_listing.txt` | same as above |
| `recent_files.txt` | same as above |
| `suid_sgid.txt` | `path mode uid gid size mtime_utc flags type` |
| `hidden_files.txt` | `path type mode uid gid size mtime_utc` |

`mode` is `0o...` octal. Timestamps are UTC `Z`. A `truncated: true` flag in
the manifest's `triage[]` means a row cap was hit.

---

## Manifest schema

`schema: "linuxdfir/collector-manifest/1"` — JSON, UTF-8.

### Top-level keys

| Key | Type | Notes |
| --- | --- | --- |
| `schema` | string | `linuxdfir/collector-manifest/1` |
| `collector` | object | `name`, `version`, `script`, `python` |
| `hostname` | string | |
| `fqdn` | string | |
| `hostname_file` | string\|null | contents of `/etc/hostname` |
| `collection_time_utc` | string | ISO-8601 `Z` |
| `collection_start_epoch` | number | unix seconds |
| `collection_end_epoch` | number | unix seconds |
| `duration_seconds` | number | |
| `running_user` | object | `name`, `uid`, `euid`, `gid`, `sudo_user`, `effective_root` |
| `kernel` | object | `sysname`, `nodename`, `release`, `version`, `machine`, `proc_version` |
| `os` | object\|null | parsed `/etc/os-release` |
| `environment` | object | `root`, `wsl`, `wsl_version`, `wsl_evidence`, `container`, `python_version`, `platform`, … |
| `timezone` | object | `name`, `source`, `utc_offset_seconds`, `utc_offset_str`, `tz_env`, … |
| `hash_algorithm` | string | always `sha256` |
| `tag` | string\|null | free-form `--tag` |
| `triage_recent_days` | number | recency window |
| `triage_prunes` | array | pruned path prefixes |
| `counts` | object | see below |
| `phases` | array | `{name, started_utc, seconds}` |
| `files` | array | see below |
| `live_commands` | array | see below |
| `triage` | array | see below |
| `skipped` | array | see below |
| `collect_log` | object | `{archive_path, sha256, size}` |

### `counts`

```json
{
  "files_total": 588, "files_ok": 486, "files_not_present": 97,
  "files_skipped": 5, "live_total": 28, "live_ok": 11,
  "live_not_present": 17, "triage_total": 6, "hashed_entries": 503,
  "skipped_total": 103, "walk_errors": 0
}
```

### `files[]` — one record per attempted artifact

| Field | Type | Meaning |
| --- | --- | --- |
| `original_path` | string | logical path on the target |
| `archive_path` | string\|null | where it landed, e.g. `evidence/etc/passwd` |
| `category` | string | `auth`, `users`, `persistence`, `system_logs`, `packages`, `web_logs`, `network`, `history`, `ssh` |
| `status` | string | `ok` \| `not_present` \| `skipped` |
| `type` | string\|null | `file`, `dir`, `symlink`, `fifo`, `socket`, `blockdev`, `chardev` |
| `sha256` | string\|null | present only when the artifact was copied and hashed |
| `reason` | string\|null | populated for `not_present`/`skipped` |
| `error_type` | string\|null | e.g. `OSError` |
| `hashable` | bool | false for symlink/metadata-only records |
| `collected_seq` | number | 1-based collection order |
| `collected_at` | string | ISO-8601 `Z` |
| `size` | number | bytes |
| `mode` | string | `0o640` |
| `mode_raw` | number | raw `stat.st_mode` |
| `uid`, `gid` | number | |
| `uname`, `gname` | string | |
| `mtime`, `ctime`, `atime` | string | ISO-8601 `Z` |
| `mtime_epoch`, `ctime_epoch`, `atime_epoch` | number | unix seconds (µs precision) |
| `suid`, `sgid` | bool | |

Extra fields on symlink records: `symlink_target`, and `masked: true` when
the target is `/dev/null`.

**Status semantics.**

- `ok` — collected (and hashed, unless a symlink record).
- `not_present` — the target does not exist; `reason` says so (including
  `not present (no glob matches)` for unfired globs). Never silent.
- `skipped` — exists but could not be read/copied (`permission denied or read
  error`, `unsupported file type`, `cannot stat`).

A record with `sha256: null` is counted by the analyzer as **metadata-only**:
it is listed in the manifest and verified as present, but has no content hash
to compare. Symlink records are the normal case.

### `live_commands[]`

```json
{
  "name": "ps_auxf", "argv": ["ps", "auxf"], "category": "processes",
  "status": "ok", "exit_code": 0, "seconds": 0.022, "reason": null,
  "archive_path": "live/ps_auxf.txt", "sha256": "…", "size": 3893,
  "has_stderr": false, "collected_seq": 1, "collected_at": "…"
}
```

`status: not_present` with `reason: "command not found: docker"` when the
binary is absent.

### `triage[]`

```json
{
  "name": "tmp_listing", "archive_path": "triage/tmp_listing.txt",
  "status": "ok", "reason": null, "sha256": "…", "size": 2050,
  "entries": 13, "truncated": false, "category": "triage_listing",
  "collected_seq": 617, "collected_at": "…"
}
```

### `skipped[]`

Flat audit trail of everything not collected:

```json
{"original_path": "docker ps -a", "category": "containers",
 "status": "not_present", "reason": "command not found: docker"}
```

---

## Integrity verification

`linuxdfir verify` re-reads every manifest entry and compares:

| Result | Meaning |
| --- | --- |
| `ok` | member present, `sha256` matches |
| `mismatch` | member present, hash differs |
| `missing` | manifest expects a member that is absent |
| `extra` | archive contains a member the manifest does not reference |
| `metadata_only` | manifest record has no `sha256` to compare |

The `.sha256` sidecar is checked first (`sidecar: ok`), then per-member
hashing. Exit code `0` means integrity holds; `2` means it failed. Full
detail lands in `verify_report.json` with `integrity_ok` and per-bucket
lists.

## Analyzer outputs

`linuxdfir run` produces, in the output directory:

```
verify_report.json    integrity results
events.jsonl          one normalized event per line
findings.json         detector output (rule, severity, MITRE, refs)
risk.json             per-host score + per-finding weight breakdown
timeline.db           SQLite timeline
timeline.csv          CSV timeline
timeline_stats.json   event counts by type/time
parse_stats.json      parser coverage statistics
correlation.json      chained findings by shared entity
iocs.json             extracted indicators
report.html           offline, self-contained HTML report
findings.csv          findings for spreadsheets/ticketing
manifest.json         copy of the source manifest
```

## Parser coverage

Each parser declares `CONSUMES` — registry keys from `linuxdfir.schema`
`ARTIFACTS`, whose patterns are the match rules. Exact table:

| Parser | Consumes (artifact → patterns) |
| --- | --- |
| `auth_log` | `auth_log` → `/var/log/auth.log*`, `/var/log/secure*` |
| `auditd` | `auditd` → `/var/log/audit/audit.log*` |
| `bash_history` | `bash_history` → `/home/*/.bash_history`, `/root/.bash_history`; also `zsh_history`, `viminfo`, `python_history` |
| `cron` | `cron` → `/etc/crontab`, `/etc/anacrontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}/*`, `/var/spool/cron/**`; plus `live_crontab` → `live/crontab_*.txt` |
| `filesystem_suspicious` | `suid_sgid`, `hidden_files`, `recent_files`, `tmp_listing`, `var_tmp_listing`, `dev_shm_listing` → `triage/*.txt` |
| `journald` | `live_journal` → `live/journalctl_export.txt` |
| `ld_preload` | `ld_preload` → `/etc/ld.so.preload` |
| `live_state` | `live_ps`, `live_ss`, `live_lsof`, `live_who`, `live_last`, `live_lsmod`, `live_mount`, `live_docker` → `live/*.txt` |
| `package_logs` | `package_logs` → `/var/log/dpkg.log*`, `/var/log/apt/history.log*`, `/var/log/yum.log*`, `/var/log/yum/*`, `/var/log/dnf*` |
| `passwd_shadow_sudoers` | `passwd`, `shadow`, `group` → `/etc/passwd`, `/etc/shadow`, `/etc/group`; `sudoers` → `/etc/sudoers`, `/etc/sudoers.d/*` |
| `profile_scripts` | `profile_scripts` → `/etc/profile.d/*`, `.bashrc`, `.profile`, `.bash_profile` under `/root` and `/home/*` |
| `ssh` | `ssh` → `/etc/ssh/sshd_config`, `*/.ssh/authorized_keys`, `*/.ssh/known_hosts` |
| `syslog_kern` | `syslog` → `/var/log/syslog*`; `kern_log` → `/var/log/kern.log*` |
| `systemd_units` | `systemd_unit` → `/etc/systemd/system/*`, `/usr/lib/systemd/system/*` |
| `web_logs` | `web_logs` → nginx/apache2/httpd access and error log globs under `/var/log/` |
| `wtmp_btmp_lastlog` | `wtmp`, `btmp`, `lastlog` → `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` |

Registry keys that no parser consumes (so they are collected for the record
but never become events): `apt_term_log`, `network_config`, `live_df`,
`live_iptables`. Only `apt_term_log` is explicitly flagged
`NON_EVENT_SOURCES` ("not an event source"); the rest are simply unclaimed.

Select a subset with `--parsers <name>,<name>` or the default `all`.
