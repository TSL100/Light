# Detection catalogue

Every detector consumes the normalized `events.jsonl` produced by
`linuxdfir parse` and emits `findings.json` entries. This page documents each
detector's logic, thresholds, MITRE ATT&CK mapping, false-positive notes, and
how to tune it.

Registry (21 detectors, in `linuxdfir/detectors/__init__.py`):
`account_changes`, `audit_exec`, `executables_in_dev_shm`, `kernel_module`,
`ld_preload`, `login_anomalies`, `masked_services`, `offensive_tools`,
`package_install`, `recent_changes_in_sensitive_paths`, `remote_access`,
`ssh_bruteforce`, `ssh_keys`, `sshd_weakening`, `suspicious_containers`,
`suspicious_history`, `suspicious_processes`, `timestomp_detection`,
`tmp_persistence`, `unusual_suid`, `webshell`.

## Severities and scoring

Severities are `critical`, `high`, `medium`, `low`, `info`. They feed the host
risk score:

| Severity | Weight |
| --- | --- |
| critical | 100 |
| high | 40 |
| medium | 10 |
| low | 2 |
| info | 0 |

Score = `cap * (1 - exp(-total / cap))` after per-rule decay (`decay^i` per
additional finding of the same rule), so no single noisy rule can saturate the
score. Every contributing finding with its raw and damped weight is listed in
`risk.json` and the HTML report. Tune under `[scoring]` in `detection.toml`.

Two cross-cutting knobs apply to all detectors:

- `[severity_overrides]` — pin a rule to a fixed severity before scoring.
- `[allowlist].findings` — drop findings by `rule`, `title_contains`, and/or
  `path` substrings.

---

## `ssh_bruteforce`

**Rules:** `ssh_bruteforce_then_success` (critical), `ssh_bruteforce` (medium),
`ssh_password_spraying` (medium)

**Logic.** Groups `ssh_failed_login` / `ssh_accepted_login` events by source
IP.

| Parameter | Default |
| --- | --- |
| `fail_threshold` | 10 failures |
| `fail_window` | 600 s |
| `success_window` | 1800 s after last failure |
| `spray_threshold` | 5 distinct usernames |
| `spray_high_threshold` | 10 distinct usernames |

A success inside `success_window` and not before the first failure upgrades to
**critical** when the account is `root` or in `sudo_users`. Spraying fires when
one source fails across many distinct usernames (low-and-slow guessing).

**MITRE.** T1110.001 (brute force), T1110.003 (password spraying), T1078
(valid accounts).

**FP notes.** Scanners and misconfigured automation produce failure bursts —
that is why a burst alone is only `medium`. Confirm no accepted login from the
source in the full (non-rotated) logs. `max_refs = 6` caps references per
finding.

**Tuning.** Signature kwargs only (`fail_threshold`, `spray_threshold`, …);
raise them for noisy perimeter hosts.

## `suspicious_history`

**Rule:** `suspicious_history_commands` (severity varies)

**Logic.** Regex over shell-history events. Per-pattern severity and MITRE:

| Pattern | Severity | MITRE |
| --- | --- | --- |
| `curl\|wget ... \| sh` pipe-to-shell | high | T1059, T1105 |
| download into `/tmp`, `/dev/shm`, `/var/tmp` | high | T1105 |
| `chmod +x` on scratch paths | high | T1059 |
| `nc -e` / `ncat -e` | high | T1059 |
| `/dev/tcp` or `/dev/udp` | high | T1059 |
| `python -c` with `socket` | high | T1059 |
| `ssh-keygen` / `authorized_keys` | high | T1059 |
| `useradd` / `adduser` | high | T1059 |
| `HISTFILE=/dev/null`, `unset HISTFILE` | medium | T1070.003 |
| `history -c` | medium | T1070.003 |
| `rm` of auth/wtmp/btmp/lastlog | medium | T1070.003 |
| `crontab -r`, `chattr` | medium | T1059 |
| `base64 -d` piped to a shell or scratch path | high | T1059, T1105 |

The highest-matching severity per history file wins.

**FP notes.** Admins really do pipe `curl | sh` for bootstrap scripts. Treat the
owning account as suspect and correlate the command's timestamp with
persistence and logins.

**Tuning.** None (no config section).

## `account_changes`

**Rule:** `new_user_or_sudoers_change` (high)

**Logic.**

- More than one UID 0 account → high (T1136). Only `root` is expected.
- `NOPASSWD` sudo grants in `/etc/sudoers*`, grouped per file → high
  (T1548.003).

**FP notes.** Images occasionally ship a second UID 0 service account; diff
against a known-good baseline before escalating.

**Tuning.** None.

## `tmp_persistence`

**Rule:** `persistence_from_tmp_paths` (high)

**Logic.** Cron jobs and systemd `Exec*` lines whose command references
world-writable or hidden paths (`/tmp`, `/dev/shm`, `/var/tmp`, dotfiles).
Grouped by payload so one implant does not fan out into dozens of findings.

**MITRE.** T1053.003 (cron), T1543.002 (systemd).

**FP notes.** Legitimate packages occasionally write scratch paths into units;
verify the referenced file still exists and is trusted.

**Tuning.** None (hard-coded suspicious-path set).

## `ld_preload`

**Rule:** `ld_preload_hijack` (high)

**Logic.** Any entry in `/etc/ld.so.preload`, plus `LD_PRELOAD` exported via
environment in history/audit events.

**MITRE.** T1574.006.

**FP notes.** Rarely legitimate (some overlay/filter drivers). Because a
preloaded library is injected into nearly every process, treat the host's
monitoring output as untrustworthy until re-collected after cleanup.

**Tuning.** None.

## `ssh_keys`

**Rule:** `new_authorized_keys` (medium → high)

**Logic.**

- ≥ 2 keys in root's `authorized_keys` → high (T1098.004).
- Keys carrying `options=` (forced command, `from=`, `command=`) → medium.
- Keys on accounts whose shell is `nologin`/`false` → medium.

**FP notes.** Automation accounts legitimately hold keys. Check key mtimes
against the intrusion window and review auth logs for logins using them.

**Tuning.** None.

## `masked_services`

**Rule:** `masked_security_service` (high / low / info)

**Logic.** Units symlinked to `/dev/null` are classified:

- security services (auditd, rsyslog, firewalld, ufw, apparmor, selinux,
  aide, osquery, …) → **high**, T1562.001 / T1562.006
- known-benign masked units → **low**
- unclassified masked units → **info**

**FP notes.** Masking unused services is common systemd hygiene — the
classification is what matters, not the mere presence of a masked unit.

**Tuning.** None.

## `sshd_weakening`

**Rule:** `sshd_config_weakening` (severity per setting)

**Logic.** Matches `sshd: <key> <value>` events against:

| Setting | Bad value | Severity |
| --- | --- | --- |
| `PermitRootLogin` | yes/true | medium |
| `PermitEmptyPasswords` | yes/true | medium |
| `PasswordAuthentication` | yes/true | low |
| `ChallengeResponseAuthentication` | yes/true | low |
| `KbdInteractiveAuthentication` | yes/true | low |
| `PubkeyAuthentication` | no/false | low |
| `PermitUserEnvironment` | yes/true | low |

**MITRE.** T1078.

**FP notes.** `PasswordAuthentication yes` is still common; that is why it is
`low` and not higher.

**Tuning.** `[severity_overrides]` is the practical lever, e.g.
`sshd_config_weakening = "info"`.

## `webshell`

**Rule:** `webshell_and_web_attacks` (high / medium)

**Logic.** Two streams:

- **Files:** executable/script files under upload directories
  (`/uploads`, `/wp-content/uploads`, `/var/www/...`) from triage listings.
- **Access log:** ≥ 3 hits on such a URI, or known scanner signatures, or
  command-execution parameters (`cmd`, `exec`, `x`, `eval`, …) and injection
  probes returning 200 → **high**. A `POST` to a script that was never `GET`-ed
  → **medium**.

**MITRE.** T1190 (exploit public-facing app), T1505.003 (web shell).

**FP notes.** Scanners are constant background noise; the file-side signal and
the GET/POST asymmetry are the higher-confidence parts.

**Tuning.** None.

## `package_install`

**Rule:** `suspicious_package_install` (medium / info)

**Logic.** Matches installed package names against `[package_tools].tools`
(component match, so `netcat` hits `netcat-traditional` *and*
`netcat-openbsd`). Severity is decided by provenance:

| Condition | Severity |
| --- | --- |
| Explicitly requested on an apt command line | medium (T1588.002) |
| Part of a bulk batch ≥ `threshold` (default 50) within `window_minutes` (default 10) | **info** (provisioning) |
| In `[default_image_packages]` and not explicitly requested | **info** |
| Otherwise (no apt context) | medium |

`netcat-traditional` is deliberately excluded from the image allowlist: it is
the classic attacker choice and must always raise a finding.

**FP notes.** Image builds install dozens of packages at once — the bulk-batch
rule exists precisely for that. Confirm the batch timestamp matches a build
window before dismissing.

**Tuning.** `[package_tools]`, `[bulk_batch]`, `[default_image_packages]`.

## `audit_exec`

**Rule:** `audit_suspicious_exec` (high / medium)

**Logic.** Kernel `EXECVE` records (not wipeable by clearing history)
flagging downloaders piped to shells, reverse shells, credential-file access
(`/etc/shadow` → T1003.008, else T1059), and unprivileged audit sessions
acting as root (medium).

**FP notes.** High confidence by construction — the record comes from the
kernel, not user-writable files.

**Tuning.** None.

## `login_anomalies`

**Rule:** `login_anomalies` (medium / low / high)

**Logic.**

| Signal | Default | Severity | MITRE |
| --- | --- | --- | --- |
| Successful login from an IP with stacked failures | — | high | T1110.001, T1078 |
| `btmp` failed-login spike | `spike_threshold = 20` in `spike_window = 600` s | medium | T1110.001 |
| Login outside business hours | `[business_hours]` 08:00–18:00 local | low | T1078 |
| Direct root login from a non-local address | — | medium | T1078 |

**FP notes.** The unusual-hour rule is host-local by design; night-shift hosts
will generate noise. Gate it with `[allowlist]` on the title substring
`"Unusual-hour"` rather than disabling the whole detector.

**Tuning.** `[business_hours].start/end`, `[allowlist]`.

## `kernel_module`

**Rule:** `kernel_module_load` (medium)

**Logic.** Module loads from `kern.log`/audit that are out-of-tree, unsigned,
tainted, or otherwise outside normal package activity.

**MITRE.** T1547.006 (boot or logon autostart: kernel modules).

**FP notes.** Out-of-tree drivers (nvidia, wireguard, virtualization) are
routine; compare against `lsmod` and package provenance before escalating.

**Tuning.** None.

## `remote_access`

**Rule:** `remote_access_tooling` (low / info)

**Logic.** Tool names in cron jobs, systemd exec lines, and live processes:

| Family | Severity | MITRE |
| --- | --- | --- |
| cloudflared, ngrok, frp, chisel, ligolo | low | T1572, T1090 |
| tailscale, zerotier | info | T1572 |
| socat with tunnel-style arguments | low | T1572, T1090 |

Findings carry an explicit caveat: these are ordinary admin tools; verify
intent before escalating.

**Tuning.** None (fixed family list).

## `timestomp_detection`

**Rule:** `timestomp_detection` (high / low / info)

**Logic.** Two signals:

- **Direct:** `ctime` more than `[timestomp].threshold_days` (default **1**)
  after `mtime` → timestamps were rewritten.
- **Cohort:** within a directory, a file whose mtime is an outlier vs its
  siblings (grouped by parent directory, not globally).

Severity separates provenance-explained from unexplained cases:

| Condition | Severity |
| --- | --- |
| Scratch-space path (`/tmp`, `/var/tmp`, `/dev/shm`) with a large gap | **high** |
| Path in `[timestomp].allowlist_paths` (WSL, apt/dpkg caches) | **info** — still emitted, reason stated in the title |
| Rotated log names under `/var/log` (`.1`, `.1.gz`, `-YYYYMMDD`, `~`) | **info** |
| Other unexplained gaps | **low** |

**MITRE.** T1070.006 (timestomp).

**FP notes.** Package installs, archive extraction, and log rotation all
produce ctime/mtime gaps — this is why provenance never *suppresses* a
finding, only lowers it with the condition named in the text. Thresholds below
~1 day produce noise.

**Tuning.** `[timestomp].threshold_days`, `[timestomp].allowlist_paths`.

## `offensive_tools`

**Rule:** `offensive_tool_paths` (info / low)

**Logic.** Path-component, case-insensitive prefix matches against:

- **C2 / phishing / post-ex:** evilginx, evilgophish, gophish, mythic,
  covenant, sliver, havoc, bruteratel, cobaltstrike, metasploit, msfvenom,
  ligolo, sharpsploit, ghostpack
- **Tunnel clients:** cloudflared, ngrok, frpc, frps, localtunnel, chisel,
  gost, neo-regeorg, reGeorg, plink
- **Config extras:** `[offensive_tools].extra_names`,
  `extra_tunnel_names`

Matched against triage listings (`recent_file`, `tmp_area_file`,
`hidden_file`, `suid_sgid_file`), so `evilgophish-1` matches `evilgophish`.

**FP notes.** Presence alone does not attribute an operator. These findings
are deliberately **info/low** and are **not** subject to the timestomp
allowlist — a package path explains timestamp drift, not the presence of a
tool. Treat them as pivot points for the rest of the investigation.

**Tuning.** `[offensive_tools].extra_names`, `extra_tunnel_names`.

## `executables_in_dev_shm`

**Rule:** `executables_in_dev_shm` (high)

**Logic.** Files under `[scratch_exec].paths` (`/tmp/`, `/var/tmp/`,
`/dev/shm/`) that have the exec bit, a hidden path component, or ELF content.
`[scratch_exec].allowlist` entries (default `.placeholder`) never alert.

**MITRE.** T1105 (ingress tool transfer).

**FP notes.** Legitimate installers occasionally drop executables there;
hash the file and check whether anything references it.

**Tuning.** `[scratch_exec].paths`, `[scratch_exec].allowlist`.

## `suspicious_processes`

**Rule:** `suspicious_processes` (severity varies)

**Logic.** Live `ps`/`ss` snapshots from `live_state`:

- binaries running from scratch paths → high (T1105 / T1036 masquerading)
- reverse-shell command lines matching
  `[processes].reverse_shell_patterns` → high (T1059.004)
- miners matching `[processes].miner_patterns` → high (T1496)
- listeners on ports outside `[processes].allowed_ports` → medium

**FP notes.** `allowed_ports` covers common service ports (22, 80, 443, 53,
25, 110, 143, 993, 995, 3306, 5432, 6379, 11211). Add your own before
calling a listener suspicious.

**Tuning.** `[processes].allowed_ports`, `miner_patterns`,
`reverse_shell_patterns`.

## `unusual_suid`

**Rule:** `unusual_suid` (high / medium)

**Logic.** SUID/SGID binaries from triage:

- in world-writable paths (`[suid].writable_paths`) → **high** even if the
  name looks familiar
- outside `[suid].allowlist` → **medium**

**MITRE.** T1548.001 (setuid and setgid).

**FP notes.** Distributions ship different SUID sets — extend the allowlist
with `dpkg -S`/`rpm -qf` output for your distro rather than ignoring
findings.

**Tuning.** `[suid].allowlist`, `[suid].writable_paths`.

## `recent_changes_in_sensitive_paths`

**Rule:** `recent_changes_in_sensitive_paths` (severity varies by path class)

**Logic.** Recently modified files under `[recent_changes].paths`
(cron dirs, `sudoers.d`, `ld.so.preload`, `systemd/system`, `profile.d`)
within the recency window. `[recent_changes].allowlist_names` (default
`apt-compat`, `logrotate`, `.placeholder`, `hardening.sh`, `man-db.cron`)
are suppressed as package-manager churn.

**MITRE.** T1053.003, T1543.002, T1548.003, T1574.006 depending on path.

**FP notes.** Package upgrades legitimately touch these; diff against the
package version (`dpkg -V`, `rpm -V`) before escalating.

**Tuning.** `[recent_changes].paths`, `allowlist_names`.

## `suspicious_containers`

**Rule:** `suspicious_containers` (high / medium)

**Logic.** From container listing output:

- privileged mode, `docker.sock` mount, or host networking → **high** (T1610)
- images outside `[containers].allowlist_images` → **medium** (T1610)

**FP notes.** Internal registries and custom image names will not be in the
allowlist; add your workload images to it.

**Tuning.** `[containers].allowlist_images`.

---

## Correlation and IOCs

After detection, findings sharing an entity (IP, path, rare username) are
chained under `[correlation]`:

| Key | Default | Meaning |
| --- | --- | --- |
| `min_chain_length` | 2 | smaller components stay unchained |
| `rare_user_max_findings` | 5 | per-user cap |

IOC tables cap at `[ioc].max_per_type = 200` entries per type, with
`[ioc].suppress` for exact values to drop (e.g. a corporate egress IP).

## Tuning checklist

1. Copy `linuxdfir/detection.toml`.
2. Adjust thresholds/allowlists per host role.
3. Suppress known-good findings with `[allowlist].findings`.
4. Pin noisy rules with `[severity_overrides]`.
5. Run `linuxdfir run evidence.tar.gz -o out --config my.toml`.

Detection logic changes belong in the detector modules and their tests, not
in config — config only adjusts thresholds, lists, and weights.
