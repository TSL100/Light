#!/usr/bin/env bash
# Dumps a JSON summary of a bash-collector run to a file for the Windows
# test to read, avoiding binary/stdout round-tripping.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(dirname "$SCRIPT_DIR")}"
PY="$REPO/.wslvenv/bin/python"
WORK="$REPO/.wsl_bash_dump"
ROOT="$WORK/rootfs"
OUT="$WORK/out"
VERIFY="$WORK/verify"
DEST="$1"

rm -rf "$WORK"
mkdir -p "$ROOT/etc" "$ROOT/var/log" "$ROOT/root" "$OUT" "$VERIFY"

printf 'root:x:0:0:root:/root:/bin/bash\n' > "$ROOT/etc/passwd"
printf 'root:x:0:\n' > "$ROOT/etc/group"
printf 'root ALL=(ALL) ALL\n' > "$ROOT/etc/sudoers"
printf '127.0.0.1 localhost\n' > "$ROOT/etc/hosts"
printf 'nameserver 1.1.1.1\n' > "$ROOT/etc/resolv.conf"
printf 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n' > "$ROOT/etc/os-release"
printf 'Oct 12 03:10:22 h sshd[2101]: note\n' > "$ROOT/var/log/auth.log"
printf 'id\n' > "$ROOT/root/.bash_history"

bash "$REPO/collector/linux_collector.sh" --root "$ROOT" -o "$OUT" \
  --skip-live --tag pytest >/dev/null

"$PY" -c "import sys; sys.path.insert(0, '$REPO'); from linuxdfir.cli import main; sys.exit(main(['verify', '$OUT/evidence.tar.gz', '--report-dir', '$VERIFY']))" >/dev/null

"$PY" - "$OUT/evidence.tar.gz" "$VERIFY/verify_report.json" "$DEST" <<'PY'
import json
import sys
import tarfile

archive, report_path, dest = sys.argv[1:4]
with tarfile.open(archive, "r:gz") as tar:
    manifest = json.load(tar.extractfile("manifest.json"))
    members = tar.getnames()
report = json.load(open(report_path, encoding="utf-8"))
files = manifest.get("files", [])
summary = {
    "schema": manifest.get("schema"),
    "collector_name": (manifest.get("collector") or {}).get("name"),
    "hash_algorithm": manifest.get("hash_algorithm"),
    "tag": manifest.get("tag"),
    "files_total": len(files),
    "files_ok": [r["original_path"] for r in files if r.get("status") == "ok"],
    "files_not_present": [r["original_path"] for r in files if r.get("status") == "not_present"],
    "not_present_with_reason": all(bool(r.get("reason")) for r in files if r.get("status") == "not_present"),
    "integrity_ok": report.get("integrity_ok"),
    "members": members,
}
json.dump(summary, open(dest, "w", encoding="utf-8"), indent=2)
PY

rm -rf "$WORK"
