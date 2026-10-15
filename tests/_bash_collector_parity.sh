#!/usr/bin/env bash
# Runs the bash and Python collectors against the same fixture rootfs and
# dumps their ok/not_present splits to a JSON file for comparison on the
# Windows side.
set -euo pipefail

REPO="/mnt/c/Users/MOHAMED/Desktop/CyberSecurity/Defense/PoC1"
PY="$REPO/.wslvenv/bin/python"
WORK="$REPO/.wsl_bash_parity"
ROOT="$WORK/rootfs"
DEST="$1"

rm -rf "$WORK"
mkdir -p "$ROOT/etc" "$ROOT/var/log" "$ROOT/root" "$WORK/bash" "$WORK/py"

printf 'root:x:0:0:root:/root:/bin/bash\n' > "$ROOT/etc/passwd"
printf 'root:x:0:\n' > "$ROOT/etc/group"
printf 'root ALL=(ALL) ALL\n' > "$ROOT/etc/sudoers"
printf '127.0.0.1 localhost\n' > "$ROOT/etc/hosts"
printf 'nameserver 1.1.1.1\n' > "$ROOT/etc/resolv.conf"
printf 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n' > "$ROOT/etc/os-release"
printf 'Oct 12 03:10:22 h sshd[2101]: note\n' > "$ROOT/var/log/auth.log"
printf 'id\n' > "$ROOT/root/.bash_history"

bash "$REPO/collector/linux_collector.sh" --root "$ROOT" -o "$WORK/bash" --skip-live >/dev/null
"$PY" "$REPO/collector/linux_collector.py" --root "$ROOT" -o "$WORK/py" --skip-live >/dev/null

"$PY" - "$WORK/bash/evidence.tar.gz" "$WORK/py/evidence.tar.gz" "$DEST" <<'PY'
import json
import sys
import tarfile


def split(path):
    with tarfile.open(path, "r:gz") as tar:
        manifest = json.load(tar.extractfile("manifest.json"))
    files = manifest.get("files", [])
    ok = sorted(r["original_path"] for r in files if r.get("status") == "ok")
    np = sorted(r["original_path"] for r in files if r.get("status") == "not_present")
    return ok, np


bash_ok, bash_np = split(sys.argv[1])
py_ok, py_np = split(sys.argv[2])
json.dump(
    {
        "bash_ok": bash_ok,
        "bash_not_present": bash_np,
        "py_ok": py_ok,
        "py_not_present": py_np,
        "ok_equal": bash_ok == py_ok,
        "np_equal": bash_np == py_np,
    },
    open(sys.argv[3], "w", encoding="utf-8"),
    indent=2,
)
PY

rm -rf "$WORK"
