#!/usr/bin/env bash
# LinuxDFIR Toolkit read-only forensic collector (bash fallback).
#
# Same artifact set and the same manifest.json schema as
# collector/linux_collector.py, so the analyzer accepts either archive
# unchanged. Read-only: the target is only ever opened for reading.
#
# Hashes via sha256sum, metadata via stat, JSON assembled with python3
# (present on every distro that ships the Python collector; when python3
# is absent the collector refuses to run rather than emit a bad manifest).
#
# Skips /mnt/* and the other virtual/container mounts, records WSL and
# timezone, and logs every NOT PRESENT path to collect.log and the
# manifest's skipped[] list, never silently.
#
# Usage: sudo bash linux_collector.sh -o /safe/outside/evidence [--root /]
#        [--skip-live] [--skip-triage] [--recent-days N] [--tag TAG]
set -u

COLLECTOR_VERSION="1.1.0"
SCHEMA="linuxdfir/collector-manifest/1"
SCRIPT_NAME="linux_collector.sh"

OUTDIR=""
ROOT="/"
SKIP_LIVE=0
SKIP_TRIAGE=0
RECENT_DAYS=7
TAG=""
MAX_RECENT=20000
MAX_SUID=5000
MAX_HIDDEN=10000
MAX_LISTING=20000
MAX_SCAN=500000
CMD_TIMEOUT=60
VERBOSE=0

READ_ONLY_FILE_ROOTS="/etc /var/log /var/spool /proc /sys /dev /run /usr /bin /sbin /lib /lib64 /boot"
TRIAGE_PRUNES="/proc /sys /dev /mnt /run /snap /lost+found /var/lib/docker /var/lib/containerd /var/lib/lxc /var/lib/kubelet"
LISTING_DIRS="/tmp /var/tmp /dev/shm"

die() { echo "collector failed: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: linux_collector.sh -o OUTDIR [options]

  -o, --output DIR     output directory (required, outside the evidence root)
      --root DIR       evidence root to collect from (default: /)
      --skip-live      do not run live commands
      --skip-triage    do not run filesystem triage walks
      --recent-days N  recency window in days (default: 7)
      --max-scan N     cap on total entries in the general triage walk
      --tag TAG        free-form tag recorded in the manifest
  -v, --verbose        log progress to stderr
      --version        print version and exit
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output) OUTDIR="${2:-}"; shift 2 ;;
        --root) ROOT="${2:-}"; shift 2 ;;
        --skip-live) SKIP_LIVE=1; shift ;;
        --skip-triage) SKIP_TRIAGE=1; shift ;;
        --recent-days) RECENT_DAYS="${2:-}"; shift 2 ;;
        --max-scan) MAX_SCAN="${2:-}"; shift 2 ;;
        --tag) TAG="${2:-}"; shift 2 ;;
        -v|--verbose) VERBOSE=1; shift ;;
        --version) echo "linuxdfir-collector $COLLECTOR_VERSION"; exit 0 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown argument: $1" ;;
    esac
done

[ -n "$OUTDIR" ] || { usage >&2; die "output directory is required (-o)"; }
command -v python3 >/dev/null 2>&1 || die "python3 not found; the bash collector needs it for metadata and manifest assembly"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
command -v stat >/dev/null 2>&1 || die "stat not found"
[ -d "$ROOT" ] || die "--root $ROOT is not a directory"

case "$ROOT" in
    /|"") REAL_ROOT="/" ;;
    *) REAL_ROOT="$(cd "$ROOT" && pwd)" ;;
esac

OUTDIR_ABS="$(mkdir -p "$OUTDIR" && cd "$OUTDIR" && pwd)" || die "cannot create output directory $OUTDIR"
STAGING="$OUTDIR_ABS/.linuxdfir_staging_$$"
mkdir -p "$STAGING" || die "cannot create staging $STAGING"
trap 'rm -rf "$STAGING"' EXIT

START_EPOCH="$(date +%s)"
LOG_FILE="$STAGING/collect.log"
: > "$LOG_FILE"

FILES_JSON="$STAGING/.files.jsonl"
LIVE_JSON="$STAGING/.live.jsonl"
TRIAGE_JSON="$STAGING/.triage.jsonl"
SKIPPED_JSON="$STAGING/.skipped.jsonl"
PHASES_JSON="$STAGING/.phases.jsonl"
: > "$FILES_JSON"; : > "$LIVE_JSON"; : > "$TRIAGE_JSON"; : > "$SKIPPED_JSON"; : > "$PHASES_JSON"

log() {
    local level="$1"; shift
    local line
    line="$(date -u +%Y-%m-%dT%H:%M:%SZ)  $(printf '%-12s' "$level") $*"
    printf '%s\n' "$line" >> "$LOG_FILE"
    if [ "$VERBOSE" -eq 1 ]; then printf '%s\n' "$line" >&2; fi
}

SEQ=0
next_seq() { SEQ=$((SEQ + 1)); printf '%s' "$SEQ"; }

utc_iso() {
    local epoch="${1:-}"
    if [ -z "$epoch" ]; then
        date -u +%Y-%m-%dT%H:%M:%SZ
    else
        date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ
    fi
}

real_path() {
    local logical="$1"
    if [ "$REAL_ROOT" = "/" ]; then
        printf '%s' "$logical"
    elif [ -z "$logical" ] || [ "$logical" = "/" ]; then
        printf '%s' "$REAL_ROOT"
    else
        printf '%s/%s' "$REAL_ROOT" "${logical#/}"
    fi
}

logical_path() {
    local real="$1"
    if [ "$REAL_ROOT" = "/" ]; then
        printf '%s' "$real"
    else
        local rel="${real#"$REAL_ROOT"}"
        [ -n "$rel" ] || rel="/"
        case "$rel" in
            /*) printf '%s' "$rel" ;;
            *) printf '/%s' "$rel" ;;
        esac
    fi
}

inside() {
    local child="$1" parent="$2"
    [ "$child" = "$parent" ] && return 0
    case "$child" in
        "$parent"/*) return 0 ;;
        *) return 1 ;;
    esac
}

for ro in $READ_ONLY_FILE_ROOTS; do
    if inside "$OUTDIR_ABS" "$(real_path "$ro")"; then
        die "output directory $OUTDIR_ABS is inside evidence location $ro; choose another output path"
    fi
done
if [ "$REAL_ROOT" != "/" ] && inside "$OUTDIR_ABS" "$REAL_ROOT"; then
    die "output directory is inside the evidence root $REAL_ROOT; refusing to write into evidence"
fi

sha256_of() { sha256sum -- "$1" 2>/dev/null | awk '{print $1}'; }
stage_path() { printf '%s/%s' "$STAGING" "${1#/}"; }
ensure_dir() { mkdir -p -- "$1" 2>/dev/null; }

py() { python3 "$@"; }

# ---------------------------------------------------------------------------
# metadata_json PATH
#   stat-based metadata in the exact shape the Python collector emits.
#   Uses GNU stat only (the fallback collector targets GNU/Linux).
# ---------------------------------------------------------------------------
metadata_json() {
    local real="$1"
    local size mode mode_raw uid gid uname gname mtime_s ctime_s atime_s
    size="$(stat -c %s -- "$real" 2>/dev/null)" || return 1
    mode="$(stat -c %a -- "$real" 2>/dev/null)" || return 1
    mode_raw="$(stat -c %f -- "$real" 2>/dev/null)" || return 1
    uid="$(stat -c %u -- "$real" 2>/dev/null)" || return 1
    gid="$(stat -c %g -- "$real" 2>/dev/null)" || return 1
    uname="$(stat -c %U -- "$real" 2>/dev/null)" || uname="$uid"
    gname="$(stat -c %G -- "$real" 2>/dev/null)" || gname="$gid"
    local mtime_s ctime_s atime_s mtime_frac ctime_frac atime_frac
    mtime_s="$(stat -c %Y -- "$real" 2>/dev/null)" || return 1
    ctime_s="$(stat -c %Z -- "$real" 2>/dev/null)" || return 1
    atime_s="$(stat -c %X -- "$real" 2>/dev/null)" || return 1
    mtime_s="${mtime_s%%.*}"; ctime_s="${ctime_s%%.*}"; atime_s="${atime_s%%.*}"
    mtime_frac="$(stat -c %y -- "$real" 2>/dev/null | awk '{print $2}' | cut -d. -f2 | cut -c1-6)"
    ctime_frac="$(stat -c %z -- "$real" 2>/dev/null | awk '{print $2}' | cut -d. -f2 | cut -c1-6)"
    atime_frac="$(stat -c %x -- "$real" 2>/dev/null | awk '{print $2}' | cut -d. -f2 | cut -c1-6)"
    [ -n "$mtime_frac" ] || mtime_frac=000000
    [ -n "$ctime_frac" ] || ctime_frac=000000
    [ -n "$atime_frac" ] || atime_frac=000000
    py -c '
import datetime, json, sys
(size, mode, mode_raw, uid, gid, uname, gname,
 mtime_s, ctime_s, atime_s, mtime_frac, ctime_frac, atime_frac) = sys.argv[1:]
mode_raw_int = int(mode_raw, 16)
mode_int = int(mode, 8)
def epoch(epoch_s, frac):
    return round(float(epoch_s) + int(frac) / 1_000_000, 6)
def iso(epoch_s):
    return datetime.datetime.fromtimestamp(
        float(epoch_s), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
if mode_raw_int & 0o170000 == 0o040000:
    kind = "dir"
elif mode_raw_int & 0o170000 == 0o100000:
    kind = "file"
elif mode_raw_int & 0o170000 == 0o120000:
    kind = "symlink"
elif mode_raw_int & 0o170000 == 0o010000:
    kind = "fifo"
elif mode_raw_int & 0o170000 == 0o140000:
    kind = "socket"
elif mode_raw_int & 0o170000 == 0o060000:
    kind = "blockdev"
elif mode_raw_int & 0o170000 == 0o020000:
    kind = "chardev"
else:
    kind = "other"
print(json.dumps({
    "size": int(size),
    "mode": "0o" + format(mode_int, "o"),
    "mode_raw": mode_raw_int,
    "type": kind,
    "uid": int(uid),
    "gid": int(gid),
    "uname": uname,
    "gname": gname,
    "mtime": iso(mtime_s),
    "ctime": iso(ctime_s),
    "atime": iso(atime_s),
    "mtime_epoch": epoch(mtime_s, mtime_frac),
    "ctime_epoch": epoch(ctime_s, ctime_frac),
    "atime_epoch": epoch(atime_s, atime_frac),
    "suid": bool(mode_int & 0o4000),
    "sgid": bool(mode_int & 0o2000),
}))' "$size" "$mode" "$mode_raw" "$uid" "$gid" "$uname" "$gname" \
       "$mtime_s" "$ctime_s" "$atime_s" "$mtime_frac" "$ctime_frac" "$atime_frac"
}

# ---------------------------------------------------------------------------
# record helpers
# ---------------------------------------------------------------------------
record_skip() {
    # record_skip LOGICAL CATEGORY STATUS REASON [ERROR_TYPE]
    local logical="$1" category="$2" status="$3" reason="$4" error_type="${5:-}"
    local seq now
    seq="$(next_seq)"; now="$(utc_iso)"
    py -c '
import json, sys
logical, category, status, reason, error_type, seq, now = sys.argv[1:]
print(json.dumps({
    "original_path": logical,
    "archive_path": None,
    "category": category,
    "status": status,
    "type": None,
    "sha256": None,
    "reason": reason,
    "error_type": error_type or None,
    "collected_seq": int(seq),
    "collected_at": now,
}))' "$logical" "$category" "$status" "$reason" "$error_type" "$seq" "$now" >> "$FILES_JSON"
    py -c '
import json, sys
print(json.dumps({"original_path": sys.argv[1], "category": sys.argv[2], "status": sys.argv[3], "reason": sys.argv[4]}))' \
        "$logical" "$category" "$status" "$reason" >> "$SKIPPED_JSON"
    local level
    case "$status" in
        skipped) level="SKIP" ;;
        not_present) level="NOT PRESENT" ;;
        *) level="$(printf '%s' "$status" | tr '[:lower:]' '[:upper:]')" ;;
    esac
    log "$level" "$logical ($category): $reason"
}

record_ok_file() {
    # record_ok_file LOGICAL CATEGORY ARCHIVE_PATH META_JSON SHA256 SIZE [EXTRA_JSON]
    local logical="$1" category="$2" archive_path="$3" meta="$4" digest="$5" size="$6" extra="${7:-}"
    local seq now
    seq="$(next_seq)"; now="$(utc_iso)"
    py -c '
import json, sys
logical, category, archive_path, meta, digest, size, extra, seq, now = sys.argv[1:]
rec = {
    "original_path": logical,
    "archive_path": archive_path or None,
    "category": category,
    "status": "ok",
    "type": None,
    "sha256": digest or None,
    "reason": None,
    "error_type": None,
    "hashable": bool(digest),
    "collected_seq": int(seq),
    "collected_at": now,
}
rec.update(json.loads(meta))
if not digest:
    rec["sha256"] = None
if extra:
    rec.update(json.loads(extra))
print(json.dumps(rec))' "$logical" "$category" "$archive_path" "$meta" "$digest" "$size" "$extra" "$seq" "$now" >> "$FILES_JSON"
}

record_meta_only() {
    # record_meta_only LOGICAL CATEGORY META_JSON EXTRA_JSON
    record_ok_file "$1" "$2" "" "$3" "" 0 "$4"
}

# ---------------------------------------------------------------------------
# environment / host / timezone / os-release
# ---------------------------------------------------------------------------
detect_environment() {
    local wsl="false" wsl_version="" wsl_evidence="" container="" container_evidence=""
    local osrelease proc_version platform
    osrelease="$(cat /proc/sys/kernel/osrelease 2>/dev/null || true)"
    proc_version="$(cat /proc/version 2>/dev/null || true)"
    case "$osrelease" in
        *microsoft*|*WSL*|*wsl*)
            wsl="true"
            wsl_evidence="proc/sys/kernel/osrelease: $osrelease"
            case "$osrelease" in
                *WSL2*|*microsoft-standard*) wsl_version="2" ;;
                *) wsl_version="1" ;;
            esac
            ;;
    esac
    if [ -f "/.dockerenv" ]; then
        container="docker"; container_evidence="/.dockerenv present"
    elif [ -f "/run/.containerenv" ]; then
        container="podman"; container_evidence="/run/.containerenv present"
    elif grep -qaE '(docker|lxc|kubepods|containerd)' /proc/1/cgroup 2>/dev/null; then
        container="unknown"; container_evidence="/proc/1/cgroup mentions a container runtime"
    fi
    platform="$(uname -srmo 2>/dev/null || uname -a)"
    py -c '
import json, sys
(root, wsl, wsl_version, wsl_evidence, container, container_evidence,
 osrelease, proc_version, platform, pyver) = sys.argv[1:]
print(json.dumps({
    "root": root,
    "wsl": wsl == "true",
    "wsl_version": int(wsl_version) if wsl_version.isdigit() else None,
    "wsl_evidence": wsl_evidence or None,
    "proc_version": proc_version or None,
    "osrelease": osrelease or None,
    "container": container or None,
    "container_evidence": container_evidence or None,
    "python_version": pyver,
    "platform": platform,
}))' "$REAL_ROOT" "$wsl" "$wsl_version" "$wsl_evidence" "$container" "$container_evidence" \
      "$osrelease" "$proc_version" "$platform" "$(python3 -V 2>&1 | awk '{print $2}')" \
      > "$STAGING/.env.json"
}

detect_timezone() {
    local name="" source="" tz_env="${TZ:-}" timedatectl_out=""
    if [ -r /etc/timezone ]; then
        name="$(tr -d '\n' < /etc/timezone 2>/dev/null || true)"
        source="/etc/timezone"
    fi
    if [ -z "$name" ] && command -v timedatectl >/dev/null 2>&1; then
        name="$(timeout "$CMD_TIMEOUT" timedatectl show -p Timezone --value 2>/dev/null || true)"
        [ -n "$name" ] && source="timedatectl"
        timedatectl_out="$(timeout "$CMD_TIMEOUT" timedatectl 2>/dev/null | head -20 || true)"
    fi
    if [ -z "$name" ] && [ -L /etc/localtime ]; then
        name="$(readlink /etc/localtime | sed 's|.*/zoneinfo/||')"
        source="/etc/localtime symlink"
    fi
    if [ -z "$name" ]; then
        name="${tz_env:-UTC}"
        if [ -n "$tz_env" ]; then source="TZ env"; else source="fallback UTC"; fi
    fi
    local offset_raw offset_secs offset_str
    offset_raw="$(date +%z)"
    offset_secs="$(py -c '
import sys
raw = sys.argv[1]
sign = -1 if raw[0] == "-" else 1
print(sign * (int(raw[1:3]) * 3600 + int(raw[3:5]) * 60))' "$offset_raw")"
    offset_str="$(py -c '
import sys
raw = sys.argv[1]
print("%s%s:%s" % (raw[0], raw[1:3], raw[3:5]))' "$offset_raw")"
    py -c '
import json, sys
name, source, offset_secs, offset_str, tz_env, td = sys.argv[1:]
print(json.dumps({
    "name": name,
    "source": source,
    "utc_offset_seconds": int(offset_secs),
    "utc_offset_str": offset_str,
    "tz_env": tz_env or None,
    "timedatectl_output": td or None,
}))' "$name" "$source" "$offset_secs" "$offset_str" "$tz_env" "$timedatectl_out" \
      > "$STAGING/.tz.json"
}

detect_host() {
    local hostname="" fqdn="" hostname_file=""
    hostname="$(uname -n 2>/dev/null || true)"
    fqdn="$(hostname -f 2>/dev/null || true)"
    [ -n "$fqdn" ] || fqdn="$hostname"
    if [ -r /etc/hostname ]; then
        hostname_file="$(tr -d '\n' < /etc/hostname 2>/dev/null || true)"
    fi
    if [ "$REAL_ROOT" != "/" ] && [ -n "$hostname_file" ]; then
        hostname="$hostname_file"
    fi
    py -c '
import json, sys
h, f, hf = sys.argv[1:]
print(json.dumps({"hostname": h, "fqdn": f, "hostname_file": hf or None}))' \
        "$hostname" "$fqdn" "$hostname_file" > "$STAGING/.host.json"
}

detect_osrelease() {
    py -c '
import json, sys
data = {}
try:
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            data[key] = value.strip().strip("\"")
except OSError:
    pass
print(json.dumps(data or None))' "$(real_path /etc/os-release)" > "$STAGING/.osrel.json"
}

# ---------------------------------------------------------------------------
# file collection
# ---------------------------------------------------------------------------
declare -A COLLECTED

collect_file() {
    # collect_file LOGICAL CATEGORY
    local logical="$1" category="$2"
    if [ -n "${COLLECTED[$logical]:-}" ]; then
        log INFO "already collected $logical, skipping duplicate"
        return 0
    fi
    local real meta type
    real="$(real_path "$logical")"
    if [ ! -e "$real" ] && [ ! -L "$real" ]; then
        record_skip "$logical" "$category" "not_present" "not present"
        return 0
    fi
    if [ -L "$real" ]; then
        local target
        target="$(readlink -- "$real" 2>/dev/null || true)"
        if [ "$target" = "/dev/null" ]; then
            meta="$(metadata_json "$real" 2>/dev/null || echo '{}')"
            record_meta_only "$logical" "$category" "$meta" \
                "$(py -c 'import json,sys; print(json.dumps({"symlink_target": sys.argv[1], "masked": True, "hashable": False, "type": "symlink"}))' "$target")"
            log INFO "recorded masked unit $logical -> /dev/null (metadata only)"
            COLLECTED[$logical]="ok"
            return 0
        fi
        local resolved
        resolved="$(realpath -m -- "$(dirname "$real")/$target" 2>/dev/null || true)"
        if [ -n "$resolved" ] && [ -d "$resolved" ] && [ ! -L "$resolved" ]; then
            meta="$(metadata_json "$real" 2>/dev/null || echo '{}')"
            record_meta_only "$logical" "$category" "$meta" \
                "$(py -c 'import json,sys; print(json.dumps({"symlink_target": sys.argv[1], "hashable": False, "type": "symlink"}))' "$target")"
            log INFO "recorded directory symlink $logical -> $target (metadata only)"
            COLLECTED[$logical]="ok"
            return 0
        fi
        if [ -z "$resolved" ] || [ ! -e "$resolved" ]; then
            record_skip "$logical" "$category" "not_present" "broken symlink -> $target"
            return 0
        fi
        real="$resolved"
    fi
    meta="$(metadata_json "$real" 2>/dev/null || echo '')"
    if [ -z "$meta" ] || [ "$meta" = "{}" ]; then
        record_skip "$logical" "$category" "skipped" "cannot stat" "OSError"
        return 0
    fi
    type="$(printf '%s' "$meta" | py -c 'import json,sys; print(json.load(sys.stdin).get("type") or "")')"
    if [ "$type" = "dir" ]; then
        collect_tree "$logical" "$category"
        return 0
    fi
    if [ "$type" != "file" ]; then
        record_skip "$logical" "$category" "skipped" "unsupported file type $type"
        return 0
    fi
    local archive_path="evidence/${logical#/}"
    local stage digest size
    stage="$(stage_path "$archive_path")"
    ensure_dir "$(dirname "$stage")"
    if ! cp -- "$real" "$stage" 2>/dev/null; then
        record_skip "$logical" "$category" "skipped" "permission denied or read error" "OSError"
        return 0
    fi
    digest="$(sha256_of "$stage")"
    size="$(stat -c %s -- "$stage" 2>/dev/null || echo 0)"
    record_ok_file "$logical" "$category" "$archive_path" "$meta" "$digest" "$size"
    COLLECTED[$logical]="ok"
}

collect_tree() {
    local logical="$1" category="$2"
    local real count=0 file
    real="$(real_path "$logical")"
    while IFS= read -r -d '' file; do
        collect_file "$(logical_path "$file")" "$category"
        count=$((count + 1))
    done < <(find "$real" -xdev -type f -print0 2>/dev/null)
    [ "$count" -eq 0 ] && log INFO "directory $logical contained no regular files"
}

expand_target() {
    local target="$1" category="$2"
    case "$target" in
        *[\*\?]*)
            local pattern matches
            if [ "$REAL_ROOT" = "/" ]; then pattern="$target"; else pattern="$REAL_ROOT${target}"; fi
            matches="$(compgen -G "$pattern" 2>/dev/null | sort || true)"
            if [ -z "$matches" ]; then
                record_skip "$target" "$category" "not_present" "not present (no glob matches)"
                return 0
            fi
            while IFS= read -r match; do
                [ -n "$match" ] || continue
                collect_file "$(logical_path "$match")" "$category"
            done <<< "$matches"
            ;;
        *) collect_file "$target" "$category" ;;
    esac
}

# ---------------------------------------------------------------------------
# live state
# ---------------------------------------------------------------------------
run_live() {
    # run_live NAME CATEGORY TIMEOUT ARGV_JSON
    local name="$1" category="$2" timeout_s="$3" argv_json="$4"
    local seq now status exit_code seconds reason
    seq="$(next_seq)"; now="$(utc_iso)"
    status="ok"; reason=""; exit_code=0; seconds=0
    local first
    first="$(py -c 'import json,sys; a=json.loads(sys.argv[1]); print(a[0] if a else "")' "$argv_json")"
    if ! command -v "$first" >/dev/null 2>&1; then
        status="not_present"; reason="command not found: $first"
    fi
    local out_file="$STAGING/.live_out" err_file="$STAGING/.live_err"
    : > "$out_file"; : > "$err_file"
    if [ "$status" = "ok" ]; then
        local start end
        start="$(date +%s)"
        py -c '
import json, subprocess, sys
argv = json.loads(sys.argv[1])
timeout_s = int(sys.argv[2])
try:
    proc = subprocess.run(argv, capture_output=True, timeout=timeout_s)
    sys.stdout.buffer.write(proc.stdout)
    sys.stderr.buffer.write(proc.stderr)
    raise SystemExit(proc.returncode)
except FileNotFoundError:
    raise SystemExit(127)
except subprocess.TimeoutExpired as exc:
    if exc.stdout:
        sys.stdout.buffer.write(exc.stdout)
    raise SystemExit(124)
' "$argv_json" "$timeout_s" > "$out_file" 2> "$err_file"
        exit_code=$?
        end="$(date +%s)"
        seconds=$((end - start))
        if [ "$exit_code" -eq 124 ]; then
            status="skipped"; reason="timeout after ${timeout_s}s"
        elif [ "$exit_code" -eq 127 ]; then
            status="not_present"; reason="command not found: $first"
        fi
    fi
    if [ "$status" = "not_present" ]; then
        py -c '
import json, sys
name, argv, category, status, exit_code, seconds, reason, seq, now = sys.argv[1:]
print(json.dumps({
    "name": name, "argv": json.loads(argv), "category": category,
    "status": status, "exit_code": int(exit_code), "seconds": int(seconds),
    "reason": reason or None, "archive_path": None, "sha256": None,
    "size": 0, "has_stderr": False,
    "collected_seq": int(seq), "collected_at": now,
}))' "$name" "$argv_json" "$category" "$status" "$exit_code" "$seconds" "$reason" "$seq" "$now" >> "$LIVE_JSON"
        py -c '
import json, sys
print(json.dumps({"original_path": " ".join(json.loads(sys.argv[1])), "category": sys.argv[2], "status": sys.argv[3], "reason": sys.argv[4] or None}))' \
            "$argv_json" "$category" "$status" "$reason" >> "$SKIPPED_JSON"
        log "NOT PRESENT" "$name: $reason"
        return 0
    fi
    local has_stderr="false"
    [ -s "$err_file" ] && has_stderr="true"
    if [ "$has_stderr" = "true" ]; then
        printf '\n<<<STDERR>>>\n' >> "$out_file"
        cat "$err_file" >> "$out_file"
    fi
    if [ ! -s "$out_file" ]; then
        py -c '
import json, sys
name, argv, category, status, exit_code, seconds, has_stderr, seq, now = sys.argv[1:]
print(json.dumps({
    "name": name, "argv": json.loads(argv), "category": category,
    "status": status, "exit_code": int(exit_code), "seconds": int(seconds),
    "reason": None, "archive_path": None, "sha256": None, "size": 0,
    "has_stderr": has_stderr == "true",
    "collected_seq": int(seq), "collected_at": now,
}))' "$name" "$argv_json" "$category" "$status" "$exit_code" "$seconds" "$has_stderr" "$seq" "$now" >> "$LIVE_JSON"
        log INFO "live $name produced no output"
        return 0
    fi
    local archive_path="live/$name.txt" stage digest size
    stage="$(stage_path "$archive_path")"
    ensure_dir "$(dirname "$stage")"
    cp -- "$out_file" "$stage"
    digest="$(sha256_of "$stage")"
    size="$(stat -c %s -- "$stage" 2>/dev/null || echo 0)"
    py -c '
import json, sys
name, argv, category, status, exit_code, seconds, archive_path, digest, size, has_stderr, seq, now = sys.argv[1:]
print(json.dumps({
    "name": name, "argv": json.loads(argv), "category": category,
    "status": status, "exit_code": int(exit_code), "seconds": int(seconds),
    "reason": None, "archive_path": archive_path, "sha256": digest,
    "size": int(size), "has_stderr": has_stderr == "true",
    "collected_seq": int(seq), "collected_at": now,
}))' "$name" "$argv_json" "$category" "$status" "$exit_code" "$seconds" "$archive_path" "$digest" "$size" "$has_stderr" "$seq" "$now" >> "$LIVE_JSON"
    log INFO "live $name -> $archive_path ($size bytes, $status)"
}

phase_live() {
    local mark; mark="$(date +%s)"
    if [ "$SKIP_LIVE" -eq 1 ]; then
        log INFO "live command collection skipped (--skip-live)"
        append_phase live_state "$mark"
        return 0
    fi
    run_live ps_auxf     processes  "$CMD_TIMEOUT" '["ps","auxf"]'
    run_live ss_tulpn    network    "$CMD_TIMEOUT" '["ss","-tulpn"]'
    run_live lsof_nP     network    "$CMD_TIMEOUT" '["lsof","-nP"]'
    run_live who         sessions   "$CMD_TIMEOUT" '["who"]'
    run_live last        sessions   "$CMD_TIMEOUT" '["last"]'
    run_live lsmod       kernel     "$CMD_TIMEOUT" '["lsmod"]'
    run_live mount       filesystem "$CMD_TIMEOUT" '["mount"]'
    run_live df          filesystem "$CMD_TIMEOUT" '["df"]'
    run_live docker_ps_a containers "$CMD_TIMEOUT" '["docker","ps","-a"]'
    run_live iptables_save network  "$CMD_TIMEOUT" '["iptables-save"]'
    run_live ip6tables_save network "$CMD_TIMEOUT" '["ip6tables-save"]'
    run_live journalctl_export journal 600 '["journalctl","--no-pager","-o","short-iso"]'
    local user
    while IFS=: read -r user _ uid _ _ _ _; do
        [ -n "$user" ] || continue
        case "$uid" in ''|*[!0-9]*) continue ;; esac
        [ "$uid" -lt 0 ] && continue
        run_live "crontab_$user" persistence "$CMD_TIMEOUT" \
            "$(py -c 'import json,sys; print(json.dumps(["crontab","-l","-u",sys.argv[1]]))' "$user")"
    done < <(getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null)
    append_phase live_state "$mark"
}

# ---------------------------------------------------------------------------
# file-artifact phase
# ---------------------------------------------------------------------------
FILE_TARGETS="
/var/log/auth.log*|auth
/var/log/secure*|auth
/var/log/wtmp|auth
/var/log/btmp|auth
/var/log/lastlog|auth
/etc/passwd|users
/etc/shadow|users
/etc/group|users
/etc/sudoers|users
/etc/sudoers.d/*|users
/etc/crontab|persistence
/etc/anacrontab|persistence
/etc/cron.*|persistence
/var/spool/cron/*|persistence
/etc/systemd/system|persistence
/usr/lib/systemd/system|persistence
/etc/rc.local|persistence
/etc/profile.d/*|persistence
/etc/ld.so.preload|persistence
/var/log/syslog*|system_logs
/var/log/kern.log*|system_logs
/var/log/audit/audit.log*|system_logs
/var/log/dpkg.log*|packages
/var/log/apt/history.log*|packages
/var/log/apt/term.log*|packages
/var/log/yum.log*|packages
/var/log/yum/*|packages
/var/log/dnf*|packages
/var/log/dnf/*|packages
/var/log/nginx/*access*log*|web_logs
/var/log/nginx/*error*log*|web_logs
/var/log/apache2/*access*log*|web_logs
/var/log/apache2/*error*log*|web_logs
/var/log/httpd/*access*log*|web_logs
/var/log/httpd/*error*log*|web_logs
/etc/hosts|network
/etc/resolv.conf|network
/etc/ssh/sshd_config|network
/etc/iptables/rules.v4|network
/etc/iptables/rules.v6|network
"

PER_USER_FILES=".bashrc|persistence
.profile|persistence
.bash_profile|persistence
.bash_history|history
.zsh_history|history
.viminfo|history
.ssh/authorized_keys|ssh
.ssh/known_hosts|ssh"

phase_files() {
    local mark; mark="$(date +%s)"
    local pattern category
    while IFS='|' read -r pattern category; do
        [ -n "$pattern" ] || continue
        expand_target "$pattern" "$category"
    done <<EOF
$FILE_TARGETS
EOF
    local user home home_real name file_cat
    while IFS=: read -r user _ uid _ _ home _; do
        [ -n "$user" ] || continue
        case "$home" in /*) ;; *) continue ;; esac
        home_real="$(real_path "$home")"
        if [ ! -d "$home_real" ]; then
            log INFO "skipping user $user: home $home not present"
            continue
        fi
        while IFS='|' read -r name file_cat; do
            [ -n "$name" ] || continue
            collect_file "$home/$name" "$file_cat"
        done <<EOF
$PER_USER_FILES
EOF
    done < <(cat -- "$(real_path /etc/passwd)" 2>/dev/null || cat -- /etc/passwd 2>/dev/null)
    append_phase file_artifacts "$mark"
}

# ---------------------------------------------------------------------------
# triage phase
# ---------------------------------------------------------------------------
write_triage() {
    # write_triage NAME HEADER ROWS_FILE TRUNCATED CATEGORY [STATUS] [REASON]
    local name="$1" header="$2" rows_file="$3" truncated="$4" category="$5"
    local status="${6:-ok}" reason="${7:-}"
    local seq now archive_path stage digest size entries
    seq="$(next_seq)"; now="$(utc_iso)"
    entries="$(wc -l < "$rows_file" 2>/dev/null | tr -d ' ')"
    [ -n "$entries" ] || entries=0
    if [ "$status" != "ok" ]; then
        py -c '
import json, sys
name, category, status, reason, entries, seq, now = sys.argv[1:]
print(json.dumps({
    "name": name, "archive_path": None, "status": status,
    "reason": reason or None, "sha256": None, "size": 0,
    "entries": int(entries), "truncated": False,
    "category": category, "collected_seq": int(seq), "collected_at": now,
}))' "$name" "$category" "$status" "$reason" "$entries" "$seq" "$now" >> "$TRIAGE_JSON"
        log "NOT PRESENT" "triage listing $name: $reason"
        return 0
    fi
    archive_path="triage/$name.txt"
    stage="$(stage_path "$archive_path")"
    ensure_dir "$(dirname "$stage")"
    { printf '%s\n' "$header"; cat -- "$rows_file" 2>/dev/null; } > "$stage"
    digest="$(sha256_of "$stage")"
    size="$(stat -c %s -- "$stage" 2>/dev/null || echo 0)"
    py -c '
import json, sys
name, archive_path, category, status, truncated, digest, size, entries, seq, now = sys.argv[1:]
print(json.dumps({
    "name": name, "archive_path": archive_path, "status": status,
    "reason": None, "sha256": digest, "size": int(size),
    "entries": int(entries), "truncated": truncated == "true",
    "category": category, "collected_seq": int(seq), "collected_at": now,
}))' "$name" "$archive_path" "$category" "$status" "$truncated" "$digest" "$size" "$entries" "$seq" "$now" >> "$TRIAGE_JSON"
    log INFO "triage $name -> $archive_path ($entries rows, $size bytes)"
}

# emit_row LOGICAL META_JSON -> one TSV row on stdout
emit_row() {
    py -c '
import json, sys
logical = sys.argv[1]
try:
    meta = json.loads(sys.argv[2])
except json.JSONDecodeError:
    raise SystemExit
print("\t".join([
    logical,
    meta.get("type") or "",
    meta.get("mode") or "",
    str(meta.get("uid", "")),
    str(meta.get("gid", "")),
    str(meta.get("size", "")),
    meta.get("mtime") or "",
    meta.get("ctime") or "",
    meta.get("atime") or "",
]))' "$1" "$2" 2>/dev/null
}

phase_triage() {
    local mark; mark="$(date +%s)"
    if [ "$SKIP_TRIAGE" -eq 1 ]; then
        log INFO "filesystem triage skipped (--skip-triage)"
        append_phase filesystem_triage "$mark"
        return 0
    fi
    local prune_expr=() p
    for p in $TRIAGE_PRUNES; do
        prune_expr+=(-path "$(real_path "$p")" -prune -o)
    done
    prune_expr+=(-path "$STAGING" -prune -o)
    prune_expr+=(-path "$OUTDIR_ABS" -prune -o)

    local header_listing header_suid header_hidden header_recent
    header_listing="$(printf 'path\ttype\tmode\tuid\tgid\tsize\tmtime_utc\tctime_utc\tatime_utc')"
    header_suid="$(printf 'path\tmode\tuid\tgid\tsize\tmtime_utc\tflags\ttype')"
    header_hidden="$(printf 'path\ttype\tmode\tuid\tgid\tsize\tmtime_utc')"
    header_recent="$(printf 'path\ttype\tmode\tuid\tgid\tsize\tmtime_utc\tctime_utc\tatime_utc')"

    local dir name rows row_count
    for dir in $LISTING_DIRS; do
        rows="$STAGING/.rows"; : > "$rows"
        name="$(printf '%s' "${dir#/}" | tr '/' '_')"
        if [ ! -d "$(real_path "$dir")" ]; then
            write_triage "${name}_listing" "$header_listing" "$rows" false triage_listing not_present "not present"
            continue
        fi
        row_count=0
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            row_count=$((row_count + 1))
            [ "$row_count" -gt "$MAX_LISTING" ] && break
            local meta
            meta="$(metadata_json "$entry" 2>/dev/null || true)"
            [ -n "$meta" ] || continue
            emit_row "$(logical_path "$entry")" "$meta" >> "$rows"
        done < <(find "$(real_path "$dir")" "${prune_expr[@]}" -print 2>/dev/null | sort)
        write_triage "${name}_listing" "$header_listing" "$rows" false triage_listing
    done

    # General scan: SUID/SGID, hidden files under /home and /root, recent files.
    local scan_pairs="$STAGING/.scan_pairs"
    : > "$scan_pairs"
    local scan_truncated="false" scan_count=0 entry logical meta
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        scan_count=$((scan_count + 1))
        if [ "$scan_count" -gt "$MAX_SCAN" ]; then scan_truncated="true"; break; fi
        logical="$(logical_path "$entry")"
        case "$logical" in
            /proc/*|/sys/*|/dev/*) continue ;;
        esac
        meta="$(metadata_json "$entry" 2>/dev/null || true)"
        [ -n "$meta" ] || continue
        printf '%s\t%s\n' "$logical" "$meta" >> "$scan_pairs"
    done < <(find "$(real_path /)" "${prune_expr[@]}" -print 2>/dev/null)

    local suid_rows="$STAGING/.suid_rows" hidden_rows="$STAGING/.hidden_rows" recent_rows="$STAGING/.recent_rows"
    : > "$suid_rows"; : > "$hidden_rows"; : > "$recent_rows"
    py - "$scan_pairs" "$suid_rows" "$hidden_rows" "$recent_rows" "$RECENT_DAYS" "$MAX_SUID" "$MAX_HIDDEN" "$MAX_RECENT" <<'PYEOF'
import datetime
import json
import os
import sys

scan_pairs, suid_path, hidden_path, recent_path = sys.argv[1:5]
recent_days = int(sys.argv[5])
max_suid, max_hidden, max_recent = int(sys.argv[6]), int(sys.argv[7]), int(sys.argv[8])
cutoff = datetime.datetime.now(datetime.timezone.utc).timestamp() - recent_days * 86400

suid, hidden, recent = [], [], []
with open(scan_pairs, "r", encoding="utf-8", errors="replace") as handle:
    for line in handle:
        line = line.rstrip("\n")
        if not line:
            continue
        logical, _, raw = line.partition("\t")
        try:
            meta = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if meta.get("suid") or meta.get("sgid"):
            flags = "suid" if meta.get("suid") and not meta.get("sgid") else "sgid"
            if meta.get("suid") and meta.get("sgid"):
                flags = "suid+sgid"
            suid.append([
                logical, meta.get("mode") or "", str(meta.get("uid", "")),
                str(meta.get("gid", "")), str(meta.get("size", "")),
                meta.get("mtime") or "", flags, meta.get("type") or "",
            ])
        name = os.path.basename(logical)
        if name.startswith(".") and name not in (".", ".."):
            if logical.startswith("/home/") or logical.startswith("/root/"):
                hidden.append([
                    logical, meta.get("type") or "", meta.get("mode") or "",
                    str(meta.get("uid", "")), str(meta.get("gid", "")),
                    str(meta.get("size", "")), meta.get("mtime") or "",
                ])
        mtime_epoch = float(meta.get("mtime_epoch") or 0)
        ctime_epoch = float(meta.get("ctime_epoch") or 0)
        if mtime_epoch >= cutoff or ctime_epoch >= cutoff:
            recent.append([
                logical, meta.get("type") or "", meta.get("mode") or "",
                str(meta.get("uid", "")), str(meta.get("gid", "")),
                str(meta.get("size", "")), meta.get("mtime") or "",
                meta.get("ctime") or "", meta.get("atime") or "",
            ])

suid = suid[:max_suid]
hidden = hidden[:max_hidden]
recent = sorted(recent, key=lambda row: row[6], reverse=True)[:max_recent]

def dump(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write("\t".join(row) + "\n")

dump(suid_path, suid)
dump(hidden_path, hidden)
dump(recent_path, recent)
PYEOF
    rm -f "$scan_pairs"
    write_triage suid_sgid    "$header_suid"    "$suid_rows"    false suid_sgid
    write_triage hidden_files "$header_hidden"  "$hidden_rows"  false hidden_files
    write_triage recent_files "$header_recent"  "$recent_rows"  false recent_files
    if [ "$scan_truncated" = "true" ]; then
        log WARN "general triage scan truncated at $MAX_SCAN entries"
    fi
    append_phase filesystem_triage "$mark"
}

append_phase() {
    local name="$1" start="$2" now
    now="$(date +%s)"
    py -c '
import json, sys
name, start, end = sys.argv[1:]
print(json.dumps({"name": name, "started_utc": "", "seconds": round(float(end) - float(start), 3)}))' \
        "$name" "$start" "$now" >> "$PHASES_JSON"
}

# ---------------------------------------------------------------------------
# finalize
# ---------------------------------------------------------------------------
finalize() {
    log INFO "finalizing evidence archive"
    local end_epoch
    end_epoch="$(date +%s)"

    # Stamp phase start times: first phase starts at collection start.
    py - "$PHASES_JSON" "$START_EPOCH" <<'PYEOF'
import datetime
import json
import sys

path, start = sys.argv[1], float(sys.argv[2])
rows = []
with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if line:
            rows.append(json.loads(line))
cursor = start
for row in rows:
    row["started_utc"] = datetime.datetime.fromtimestamp(
        cursor, datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    cursor += row.get("seconds", 0)
with open(path, "w", encoding="utf-8") as handle:
    for row in rows:
        handle.write(json.dumps(row) + "\n")
PYEOF

    local log_digest log_size
    log_digest="$(sha256_of "$LOG_FILE")"
    log_size="$(stat -c %s -- "$LOG_FILE" 2>/dev/null || echo 0)"

    py - "$FILES_JSON" "$LIVE_JSON" "$TRIAGE_JSON" "$SKIPPED_JSON" "$STAGING/.counts.json" <<'PYEOF'
import json
import sys

def load(path):
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except OSError:
        pass
    return rows

files, live, triage, skipped = (load(p) for p in sys.argv[1:5])
counts = {
    "files_total": len(files),
    "files_ok": sum(1 for r in files if r.get("status") == "ok"),
    "files_not_present": sum(1 for r in files if r.get("status") == "not_present"),
    "files_skipped": sum(1 for r in files if r.get("status") == "skipped"),
    "live_total": len(live),
    "live_ok": sum(1 for r in live if r.get("status") == "ok"),
    "live_not_present": sum(1 for r in live if r.get("status") == "not_present"),
    "triage_total": len(triage),
    "hashed_entries": sum(1 for r in live if r.get("sha256"))
    + sum(1 for r in triage if r.get("sha256"))
    + sum(1 for r in files if r.get("sha256")),
    "skipped_total": len(skipped),
    "walk_errors": 0,
}
with open(sys.argv[5], "w", encoding="utf-8") as handle:
    json.dump(counts, handle)
PYEOF

    py - "$STAGING" "$SCHEMA" "$COLLECTOR_VERSION" "$SCRIPT_NAME" \
        "$START_EPOCH" "$end_epoch" "$TAG" "$RECENT_DAYS" "$TRIAGE_PRUNES" \
        "$log_digest" "$log_size" <<'PYEOF'
import datetime
import json
import os
import platform
import sys

(staging, schema, version, script, start, end, tag, recent_days, prunes,
 log_digest, log_size) = sys.argv[1:]

def load(name):
    with open(os.path.join(staging, name), "r", encoding="utf-8") as handle:
        text = handle.read().strip()
        return json.loads(text) if text else None

def load_rows(name):
    rows = []
    path = os.path.join(staging, name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    return rows

files = load_rows(".files.jsonl")
live = load_rows(".live.jsonl")
triage = load_rows(".triage.jsonl")
skipped = load_rows(".skipped.jsonl")
phases = load_rows(".phases.jsonl")
counts = load(".counts.json")
environment = load(".env.json") or {}
timezone_info = load(".tz.json") or {}
host = load(".host.json") or {}
os_release = load(".osrel.json")

def iso(epoch):
    return datetime.datetime.fromtimestamp(
        float(epoch), datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

def kernel_info():
    info = {}
    for key, path in (("proc_version", "/proc/version"),
                      ("osrelease", "/proc/sys/kernel/osrelease")):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                info[key] = handle.read().strip()
        except OSError:
            pass
    return info

try:
    import pwd
    running_user = pwd.getpwuid(os.getuid()).pw_name
except Exception:
    running_user = str(os.getuid())

manifest = {
    "schema": schema,
    "collector": {
        "name": "linuxdfir-collector",
        "version": version,
        "script": script,
        "python": platform.python_version(),
    },
    "hostname": host.get("hostname"),
    "fqdn": host.get("fqdn"),
    "hostname_file": host.get("hostname_file"),
    "collection_time_utc": iso(start),
    "collection_start_epoch": round(float(start), 6),
    "collection_end_epoch": round(float(end), 6),
    "duration_seconds": round(float(end) - float(start), 3),
    "running_user": running_user,
    "kernel": dict(kernel_info(), proc_version=environment.get("proc_version")),
    "os": os_release,
    "environment": environment,
    "timezone": timezone_info,
    "hash_algorithm": "sha256",
    "tag": tag or None,
    "triage_recent_days": int(recent_days),
    "triage_prunes": prunes.split(),
    "counts": counts,
    "phases": phases,
    "files": files,
    "live_commands": live,
    "triage": triage,
    "skipped": skipped,
    "collect_log": {
        "archive_path": "collect.log",
        "sha256": log_digest,
        "size": int(log_size),
    },
}
with open(os.path.join(staging, "manifest.json"), "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2, sort_keys=False, default=str)
PYEOF

    local tar_path="$OUTDIR_ABS/evidence.tar.gz" tmp_tar
    tmp_tar="$tar_path.partial"
    (
        cd "$STAGING" || exit 1
        members="manifest.json
collect.log"
        for dir in evidence live triage; do
            if [ -d "$dir" ]; then
                while IFS= read -r -d '' f; do
                    members="$members
$f"
                done < <(find "$dir" -type f -print0 | sort -z)
            fi
        done
        printf '%s\n' "$members" | tar -czf "$tmp_tar" -T -
    )
    mv -f "$tmp_tar" "$tar_path"
    local tar_digest
    tar_digest="$(sha256_of "$tar_path")"
    printf '%s  %s\n' "$tar_digest" "evidence.tar.gz" > "$tar_path.sha256"

    echo "evidence archive : $tar_path"
    echo "archive sha256   : $tar_digest"
    py -c '
import json, sys
c = json.load(open(sys.argv[1]))
print("files ok/missing/skipped: %d / %d / %d" % (c["files_ok"], c["files_not_present"], c["files_skipped"]))
print("live commands ok/missing: %d / %d" % (c["live_ok"], c["live_not_present"]))
print("triage listings  : %d" % c["triage_total"])
print("manifest counts   : see manifest.json -> counts")
' "$STAGING/.counts.json"
    if [ -n "$TAG" ]; then echo "tag               : $TAG"; fi
}

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
log INFO "LinuxDFIR collector $COLLECTOR_VERSION starting (bash fallback)"
log INFO "evidence root: $REAL_ROOT"
log INFO "output dir: $OUTDIR_ABS"

detect_environment
detect_timezone
detect_host
detect_osrelease

py -c '
import json, sys
host = json.load(open(sys.argv[1]))
env = json.load(open(sys.argv[2]))
tz = json.load(open(sys.argv[3]))
print("host: %s (wsl=%s, tz=%s)" % (host.get("hostname"), env.get("wsl"), tz.get("name")))' \
    "$STAGING/.host.json" "$STAGING/.env.json" "$STAGING/.tz.json"

phase_live
phase_files
phase_triage
finalize
exit 0
