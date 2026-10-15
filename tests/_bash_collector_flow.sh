#!/usr/bin/env bash
# End-to-end flow for the bash fallback collector, run under WSL.
# Collects from a synthetic rootfs, then verifies the archive with the
# analyzer. Prints the analyzer's summary lines so the caller can assert.
set -euo pipefail

REPO="/mnt/c/Users/MOHAMED/Desktop/CyberSecurity/Defense/PoC1"
PY="$REPO/.wslvenv/bin/python"
WORK="$REPO/.wsl_bash_flow"
ROOT="$WORK/rootfs"
OUT="$WORK/out"
VERIFY="$WORK/verify"

rm -rf "$WORK"
mkdir -p "$ROOT/etc" "$ROOT/var/log" "$ROOT/root" "$OUT" "$VERIFY"

printf 'root:x:0:0:root:/root:/bin/bash\n' > "$ROOT/etc/passwd"
printf 'root:x:0:\n' > "$ROOT/etc/group"
printf 'root ALL=(ALL) ALL\n' > "$ROOT/etc/sudoers"
printf '127.0.0.1 localhost\n' > "$ROOT/etc/hosts"
printf 'nameserver 1.1.1.1\n' > "$ROOT/etc/resolv.conf"
printf 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n' > "$ROOT/etc/os-release"
printf 'Oct 12 03:10:22 h sshd[2101]: Failed password for root from 203.0.113.5 port 51299 ssh2\n' > "$ROOT/var/log/auth.log"
printf 'Oct 12 03:12:44 h sshd[2109]: Accepted password for root from 203.0.113.5 port 51400 ssh2\n' >> "$ROOT/var/log/auth.log"
printf 'id\n' > "$ROOT/root/.bash_history"

bash "$REPO/collector/linux_collector.sh" --root "$ROOT" -o "$OUT" \
  --skip-live --tag wsl-e2e

"$PY" -c "import sys; sys.path.insert(0, '$REPO'); from linuxdfir.cli import main; sys.exit(main(['verify', '$OUT/evidence.tar.gz', '--report-dir', '$VERIFY']))"

cat "$VERIFY/verify_report.json" | "$PY" -c "import json,sys; d=json.load(sys.stdin); print('integrity_ok:', d['integrity_ok'])"
"$PY" - <<PY
import json, tarfile
with tarfile.open("$OUT/evidence.tar.gz", "r:gz") as t:
    m = json.load(t.extractfile("manifest.json"))
files = m.get("files", [])
ok = [r for r in files if r.get("status") == "ok"]
np = [r for r in files if r.get("status") == "not_present"]
print("files ok/not_present: %d / %d" % (len(ok), len(np)))
print("schema:", m.get("schema"))
print("hash_algorithm:", m.get("hash_algorithm"))
PY

rm -rf "$WORK"
