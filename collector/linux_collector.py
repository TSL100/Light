#!/usr/bin/env python3
"""
LinuxDFIR Toolkit - host collector (single file, standard library only).

Read-only evidence acquisition for authorized incident response and forensics.
Collects artifacts and volatile command output from a Linux host, records
SHA256 hashes and full file metadata in manifest.json, and writes one
evidence.tar.gz plus its SHA256 into the directory given with -o.

The collector never writes, deletes or modifies anything under the evidence
roots it reads from. Every missing file, unreadable file or failed command is
recorded as "not present" or "skipped" in the manifest and in collect.log; the
collector keeps going.

Examples:
    python3 linux_collector.py -o /var/tmp/case123
    python3 linux_collector.py -o ./out --root /mnt/image --skip-live
    python3 linux_collector.py -o ./out --skip-triage -v

--root lets you point at a mounted forensic image instead of the running
system. Live command output is always collected from the *current* host,
independent of --root (use --skip-live when imaging an offline disk).
"""

from __future__ import print_function

import argparse
import glob as globmod
import hashlib
import json
import os
import platform
import shutil
import socket
import stat as statmod
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone

try:
    import getpass
except ImportError:
    getpass = None

try:
    import grp
except ImportError:
    grp = None

try:
    import pwd
except ImportError:
    pwd = None

COLLECTOR_VERSION = "1.0.0"
SCHEMA = "linuxdfir/collector-manifest/1"
CHUNK = 1024 * 1024
SEPARATOR = b"\n<<<STDERR>>>\n"

READ_ONLY_FILE_ROOTS = (
    "/etc",
    "/var/log",
    "/var/spool",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
)

TRIAGE_PRUNES = (
    "/proc",
    "/sys",
    "/dev",
    "/mnt",
    "/run",
    "/snap",
    "/lost+found",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/lxc",
    "/var/lib/kubelet",
)

LISTING_DIRS = ("/tmp", "/var/tmp", "/dev/shm")

DEFAULT_MAX_RECENT = 20000
DEFAULT_MAX_SUID = 5000
DEFAULT_MAX_HIDDEN = 10000
DEFAULT_MAX_LISTING = 20000
DEFAULT_MAX_SCAN = 500000
DEFAULT_MAX_FILES_PER_TREE = 50000
DEFAULT_MAX_USERS = 500
DEFAULT_CMD_TIMEOUT = 60
DEFAULT_JOURNAL_TIMEOUT = 600

LIVE_SPECS = (
    ("ps_auxf", ("ps", "auxf"), "processes"),
    ("ss_tulpn", ("ss", "-tulpn"), "network"),
    ("lsof_nP", ("lsof", "-nP"), "network"),
    ("who", ("who",), "sessions"),
    ("last", ("last",), "sessions"),
    ("lsmod", ("lsmod",), "kernel"),
    ("mount", ("mount",), "filesystem"),
    ("df", ("df",), "filesystem"),
    ("docker_ps_a", ("docker", "ps", "-a"), "containers"),
    ("iptables_save", ("iptables-save",), "network"),
    ("ip6tables_save", ("ip6tables-save",), "network"),
    ("journalctl_export", ("journalctl", "--no-pager", "-o", "short-iso"), "journal"),
)

FILE_TARGETS = (
    ("/var/log/auth.log*", "auth"),
    ("/var/log/secure*", "auth"),
    ("/var/log/wtmp", "auth"),
    ("/var/log/btmp", "auth"),
    ("/var/log/lastlog", "auth"),
    ("/etc/passwd", "users"),
    ("/etc/shadow", "users"),
    ("/etc/group", "users"),
    ("/etc/sudoers", "users"),
    ("/etc/sudoers.d/*", "users"),
    ("/etc/crontab", "persistence"),
    ("/etc/cron.*", "persistence"),
    ("/var/spool/cron/*", "persistence"),
    ("/etc/systemd/system", "persistence"),
    ("/usr/lib/systemd/system", "persistence"),
    ("/etc/rc.local", "persistence"),
    ("/etc/profile.d/*", "persistence"),
    ("/etc/ld.so.preload", "persistence"),
    ("/var/log/syslog*", "system_logs"),
    ("/var/log/kern.log*", "system_logs"),
    ("/var/log/audit/audit.log*", "system_logs"),
    ("/var/log/dpkg.log*", "packages"),
    ("/var/log/apt/history.log*", "packages"),
    ("/var/log/apt/term.log*", "packages"),
    ("/var/log/yum.log*", "packages"),
    ("/var/log/yum/*", "packages"),
    ("/var/log/dnf*", "packages"),
    ("/var/log/dnf/*", "packages"),
    ("/var/log/nginx/*access*log*", "web_logs"),
    ("/var/log/nginx/*error*log*", "web_logs"),
    ("/var/log/apache2/*access*log*", "web_logs"),
    ("/var/log/apache2/*error*log*", "web_logs"),
    ("/var/log/httpd/*access*log*", "web_logs"),
    ("/var/log/httpd/*error*log*", "web_logs"),
    ("/etc/hosts", "network"),
    ("/etc/resolv.conf", "network"),
    ("/etc/ssh/sshd_config", "network"),
    ("/etc/iptables/rules.v4", "network"),
    ("/etc/iptables/rules.v6", "network"),
)

PER_USER_FILES = (
    (".bashrc", "persistence"),
    (".profile", "persistence"),
    (".bash_profile", "persistence"),
    (".bash_history", "history"),
    (".zsh_history", "history"),
    (".viminfo", "history"),
    (".ssh/authorized_keys", "ssh"),
    (".ssh/known_hosts", "ssh"),
)

IGNORED_HOMES = (
    "",
    "/",
    "/nonexistent",
    "/sbin",
    "/bin",
    "/usr/sbin",
    "/usr/bin",
    "/var/empty",
    "/var/spool/mail",
)


def _utc_iso(ts=None):
    if ts is None:
        ts = time.time()
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lstat(path):
    return os.lstat(path)


def _makedirs(path):
    if path and not os.path.isdir(path):
        os.makedirs(path)


def _is_within(child, parent):
    child = os.path.normcase(os.path.normpath(child))
    parent = os.path.normcase(os.path.normpath(parent))
    if child == parent:
        return True
    return child.startswith(parent + os.sep)


def _remove_readonly(func, path, _exc):
    try:
        os.chmod(path, statmod.S_IWRITE | statmod.S_IREAD | statmod.S_IEXEC)
        func(path)
    except OSError:
        pass


def _rmtree(path):
    shutil.rmtree(path, onerror=_remove_readonly)


def _owner_names(st):
    uname = str(st.st_uid)
    gname = str(st.st_gid)
    if pwd is not None:
        try:
            uname = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            pass
    if grp is not None:
        try:
            gname = grp.getgrgid(st.st_gid).gr_name
        except Exception:
            pass
    return uname, gname


def _entry_type(mode):
    if statmod.S_ISREG(mode):
        return "file"
    if statmod.S_ISDIR(mode):
        return "dir"
    if statmod.S_ISLNK(mode):
        return "symlink"
    if statmod.S_ISFIFO(mode):
        return "fifo"
    if statmod.S_ISSOCK(mode):
        return "socket"
    if statmod.S_ISBLK(mode):
        return "blockdev"
    if statmod.S_ISCHR(mode):
        return "chardev"
    return "other"


def _has_magic(text):
    return any(ch in text for ch in "*?[")


def _copy_hash(src, dst):
    digest = hashlib.sha256()
    _makedirs(os.path.dirname(dst))
    written = 0
    with open(src, "rb") as fin:
        with open(dst, "wb") as fout:
            while True:
                buf = fin.read(CHUNK)
                if not buf:
                    break
                fout.write(buf)
                digest.update(buf)
                written += len(buf)
    return digest.hexdigest(), written


def _run(argv, timeout=DEFAULT_CMD_TIMEOUT):
    result = {
        "argv": list(argv),
        "status": "ok",
        "exit_code": None,
        "stdout": b"",
        "stderr": b"",
        "seconds": 0.0,
        "reason": None,
    }
    if not argv:
        result["status"] = "error"
        result["reason"] = "empty command"
        return result
    if shutil.which(argv[0]) is None:
        result["status"] = "not_present"
        result["reason"] = "command not found: %s" % argv[0]
        return result
    start = time.time()
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        result["status"] = "error"
        result["reason"] = "%s: %s" % (type(exc).__name__, exc)
        result["seconds"] = round(time.time() - start, 3)
        return result
    try:
        out, err = proc.communicate(timeout=timeout)
        result["exit_code"] = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        result["exit_code"] = proc.returncode
        result["status"] = "timeout"
        result["reason"] = "timed out after %ss" % timeout
    except OSError as exc:
        proc.kill()
        out, err = b"", b""
        result["status"] = "error"
        result["reason"] = "%s: %s" % (type(exc).__name__, exc)
    result["seconds"] = round(time.time() - start, 3)
    result["stdout"] = out or b""
    result["stderr"] = err or b""
    if result["status"] == "ok" and result["exit_code"] not in (0, None):
        if not (result["stdout"] or result["stderr"]):
            result["status"] = "error"
            result["reason"] = "exit code %s" % result["exit_code"]
    return result


def walk_entries(top, prunes, onerror=None, max_entries=0, state=None):
    """Yield (real_path, is_dir) for every entry under top, honouring prunes."""
    if state is None:
        state = {}
    pruneset = set()
    for prune in prunes:
        pruneset.add(os.path.normcase(os.path.normpath(prune)))
    if os.path.normcase(os.path.normpath(top)) in pruneset:
        return
    stack = [top]
    visited = 0
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda e: e.name)
        except OSError as exc:
            if onerror is not None:
                onerror(current, exc)
            continue
        subdirs = []
        for entry in entries:
            visited += 1
            if max_entries and visited > max_entries:
                state["truncated"] = True
                return
            try:
                is_link = entry.is_symlink()
            except OSError as exc:
                if onerror is not None:
                    onerror(entry.path, exc)
                continue
            if is_link:
                yield (entry.path, False)
                continue
            try:
                is_dir = entry.is_dir()
            except OSError as exc:
                if onerror is not None:
                    onerror(entry.path, exc)
                continue
            if is_dir:
                if os.path.normcase(os.path.normpath(entry.path)) in pruneset:
                    continue
                subdirs.append(entry.path)
            yield (entry.path, is_dir)
        for path in reversed(subdirs):
            stack.append(path)


def parse_os_release(root):
    path = os.path.join(root.lstrip("/") if root != "/" else "", "etc", "os-release")
    if root != "/":
        path = os.path.join(root, "etc", "os-release")
    info = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                info[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        return None
    return info


def detect_timezone(root):
    result = {
        "name": None,
        "source": None,
        "utc_offset_seconds": None,
        "utc_offset_str": None,
        "tz_env": os.environ.get("TZ"),
        "tzname": list(time.tzname) if isinstance(time.tzname, (list, tuple)) else [str(time.tzname)],
    }
    try:
        now_local = datetime.now().astimezone()
        offset = now_local.utcoffset()
        if offset is not None:
            result["utc_offset_seconds"] = int(offset.total_seconds())
            total = int(offset.total_seconds())
            sign = "+" if total >= 0 else "-"
            total = abs(total)
            result["utc_offset_str"] = "%s%02d%02d" % (sign, total // 3600, (total % 3600) // 60)
    except Exception:
        pass
    if root == "/":
        probe = _run(("timedatectl", "show", "-p", "Timezone", "--value"), timeout=10)
        if probe["status"] == "ok" and probe["stdout"]:
            name = probe["stdout"].decode("utf-8", "replace").strip()
            if name:
                result["name"] = name
                result["source"] = "timedatectl"
                result["timedatectl_output"] = name
    if result["name"] is None:
        path = os.path.join(root, "etc", "timezone") if root != "/" else "/etc/timezone"
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                name = handle.read().strip()
            if name:
                result["name"] = name
                result["source"] = "/etc/timezone"
        except OSError:
            pass
    if result["name"] is None:
        link = os.path.join(root, "etc", "localtime") if root != "/" else "/etc/localtime"
        try:
            target = os.readlink(link)
            marker = "zoneinfo/"
            if marker in target:
                result["name"] = target.split(marker, 1)[1].strip("/")
                result["source"] = "/etc/localtime"
        except OSError:
            pass
    if result["name"] is None and result["tz_env"]:
        result["name"] = result["tz_env"].split(":", 1)[-1]
        result["source"] = "TZ"
    if result["name"] is None and result["utc_offset_str"] is not None:
        result["source"] = "utc_offset"
    return result


def detect_environment(root):
    env = {
        "root": root,
        "wsl": False,
        "wsl_version": None,
        "wsl_evidence": None,
        "proc_version": None,
        "osrelease": None,
        "container": None,
        "container_evidence": None,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }
    for rel in ("proc/version", "proc/sys/kernel/osrelease"):
        path = os.path.join(root, rel) if root != "/" else "/" + rel
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                content = handle.read().strip()
        except OSError:
            continue
        if rel.endswith("osrelease"):
            env["osrelease"] = content
        else:
            env["proc_version"] = content
        if "microsoft" in content.lower():
            env["wsl"] = True
            env["wsl_evidence"] = "%s: %s" % (rel, content[:300])
            if "wsl2" in content.lower() or "microsoft-standard" in content.lower():
                env["wsl_version"] = 2
            elif env["wsl_version"] is None:
                env["wsl_version"] = 1
    dockerenv = os.path.join(root, ".dockerenv") if root != "/" else "/.dockerenv"
    if os.path.exists(dockerenv):
        env["container"] = "docker"
        env["container_evidence"] = dockerenv
    else:
        cgroup = os.path.join(root, "proc/1/cgroup") if root != "/" else "/proc/1/cgroup"
        try:
            with open(cgroup, "r", encoding="utf-8", errors="replace") as handle:
                data = handle.read(65536).lower()
            for token in ("docker", "containerd", "kubepods", "lxc", "podman"):
                if token in data:
                    env["container"] = token
                    env["container_evidence"] = cgroup
                    break
        except OSError:
            pass
    return env


def kernel_info():
    info = {
        "sysname": None,
        "nodename": None,
        "release": None,
        "version": None,
        "machine": None,
    }
    try:
        uname = os.uname()
    except (AttributeError, OSError):
        for key, value in zip(
            ("sysname", "nodename", "release", "version", "machine"),
            (platform.system(), platform.node(), platform.release(), platform.version(), platform.machine()),
        ):
            info[key] = value
        return info
    info["sysname"] = uname.sysname
    info["nodename"] = uname.nodename
    info["release"] = uname.release
    info["version"] = uname.version
    info["machine"] = uname.machine
    return info


def running_user():
    uid = os.getuid() if hasattr(os, "getuid") else None
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    gid = os.getgid() if hasattr(os, "getgid") else None
    name = None
    if pwd is not None and uid is not None:
        try:
            name = pwd.getpwuid(uid).pw_name
        except Exception:
            name = None
    if name is None and getpass is not None:
        try:
            name = getpass.getuser()
        except Exception:
            name = None
    return {
        "name": name,
        "uid": uid,
        "euid": euid,
        "gid": gid,
        "sudo_user": os.environ.get("SUDO_USER"),
        "effective_root": euid == 0 if euid is not None else None,
    }


def read_passwd(root, limit=DEFAULT_MAX_USERS):
    path = os.path.join(root, "etc", "passwd") if root != "/" else "/etc/passwd"
    entries = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.rstrip("\n").split(":")
                if len(parts) < 6 or not parts[0]:
                    continue
                entries.append(
                    {
                        "name": parts[0],
                        "uid": parts[2],
                        "gid": parts[3],
                        "home": parts[5],
                        "shell": parts[6] if len(parts) > 6 else "",
                    }
                )
    except OSError:
        entries = []
    if not entries:
        homes = ["/root"]
        home_glob = os.path.join(root, "home", "*") if root != "/" else "/home/*"
        try:
            for match in sorted(globmod.glob(home_glob)):
                homes.append(os.path.basename(match))
        except OSError:
            pass
        for home in homes:
            entries.append(
                {
                    "name": os.path.basename(home) or home,
                    "uid": None,
                    "gid": None,
                    "home": home,
                    "shell": "",
                }
            )
    filtered = []
    seen = set()
    for entry in entries:
        home = entry["home"]
        if home in IGNORED_HOMES or not home.startswith("/"):
            continue
        key = (entry["name"], home)
        if key in seen:
            continue
        seen.add(key)
        filtered.append(entry)
        if len(filtered) >= limit:
            break
    return filtered


class Collector(object):
    def __init__(self, outdir, root="/", opts=None):
        self.outdir = os.path.abspath(outdir)
        self.root = "/" if root in ("/", "") else os.path.abspath(root)
        self.opts = opts or argparse.Namespace()
        self.opts.skip_live = getattr(self.opts, "skip_live", False)
        self.opts.skip_triage = getattr(self.opts, "skip_triage", False)
        self.opts.tag = getattr(self.opts, "tag", None)
        self.verbose = getattr(self.opts, "verbose", False)
        self.seq = 0
        self.started = time.time()
        self.log_lines = []
        self.files = []
        self.live = []
        self.triage = []
        self.skipped = []
        self.phases = []
        self.error_log_count = 0
        self.error_log_cap = 1000
        self.staging = os.path.join(self.outdir, ".linuxdfir_staging_%d" % os.getpid())
        self.timezone = None
        self.environment = None
        self.os_release = None

    def _real(self, logical):
        if self.root == "/":
            return logical
        if logical in ("/", ""):
            return self.root
        return os.path.join(self.root, logical.lstrip("/").replace("/", os.sep))

    def _logical(self, real):
        if self.root == "/":
            return real if real.startswith("/") else "/" + real.replace(os.sep, "/")
        rel = os.path.relpath(real, self.root)
        if rel in (".", ""):
            return "/"
        return "/" + rel.replace(os.sep, "/")

    def _stage_path(self, archive_path):
        return os.path.join(self.staging, *archive_path.split("/"))

    def log(self, level, message):
        line = "%s  %-12s %s" % (_utc_iso(), level, message)
        self.log_lines.append(line)
        if self.verbose:
            print(line, file=sys.stderr)

    def _next_seq(self):
        self.seq += 1
        return self.seq

    def _phase(self, name):
        self.phases.append({"name": name, "started_utc": _utc_iso(), "seconds": 0.0})
        return time.time()

    def _end_phase(self, mark):
        self.phases[-1]["seconds"] = round(time.time() - mark, 3)

    def _record_skip(self, logical, category, status, reason, error_type=None, extra=None):
        rec = {
            "original_path": logical,
            "archive_path": None,
            "category": category,
            "status": status,
            "type": None,
            "sha256": None,
            "reason": reason,
            "error_type": error_type,
            "collected_seq": self._next_seq(),
            "collected_at": _utc_iso(),
        }
        if extra:
            rec.update(extra)
        self.files.append(rec)
        self.skipped.append(
            {
                "original_path": logical,
                "category": category,
                "status": status,
                "reason": reason,
            }
        )
        self.log(status.upper() if status != "skipped" else "SKIP", "%s (%s): %s" % (logical, category, reason))
        return rec

    def _stat_meta(self, st):
        uname, gname = _owner_names(st)
        return {
            "size": st.st_size,
            "mode": oct(statmod.S_IMODE(st.st_mode)),
            "mode_raw": st.st_mode,
            "type": _entry_type(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "uname": uname,
            "gname": gname,
            "mtime": _utc_iso(st.st_mtime),
            "ctime": _utc_iso(st.st_ctime),
            "atime": _utc_iso(st.st_atime),
            "mtime_epoch": round(st.st_mtime, 6),
            "ctime_epoch": round(st.st_ctime, 6),
            "atime_epoch": round(st.st_atime, 6),
            "suid": bool(st.st_mode & statmod.S_ISUID),
            "sgid": bool(st.st_mode & statmod.S_ISGID),
        }

    def collect_path(self, logical, category):
        real = self._real(logical)
        try:
            st_link = _lstat(real)
        except FileNotFoundError:
            return self._record_skip(logical, category, "not_present", "not present")
        except OSError as exc:
            return self._record_skip(logical, category, "skipped", str(exc), type(exc).__name__)

        link_target = None
        st = st_link
        if statmod.S_ISLNK(st_link.st_mode):
            try:
                link_target = os.readlink(real)
            except OSError as exc:
                return self._record_skip(
                    logical, category, "skipped", "unreadable symlink: %s" % exc, type(exc).__name__
                )
            if link_target == "/dev/null":
                rec = self._base_record(logical, category, "ok", "symlink", None)
                rec.update(self._stat_meta(st_link))
                rec["type"] = "symlink"
                rec["symlink_target"] = link_target
                rec["masked"] = True
                rec["hashable"] = False
                self.files.append(rec)
                self.log("INFO", "recorded masked unit %s -> /dev/null (metadata only)" % logical)
                return rec
            resolved = os.path.normpath(os.path.join(os.path.dirname(real), link_target))
            hops = 0
            seen = set()
            while os.path.islink(resolved) and hops < 4 and resolved not in seen:
                seen.add(resolved)
                try:
                    target = os.readlink(resolved)
                except OSError:
                    break
                resolved = os.path.normpath(os.path.join(os.path.dirname(resolved), target))
                hops += 1
            if os.path.isdir(resolved) and not os.path.islink(resolved):
                rec = self._base_record(logical, category, "ok", "symlink", None)
                rec["symlink_target"] = link_target
                rec["hashable"] = False
                rec.update(self._stat_meta(st_link))
                rec["type"] = "symlink"
                self.files.append(rec)
                self.log("INFO", "recorded directory symlink %s -> %s (metadata only)" % (logical, link_target))
                return rec
            if not os.path.lexists(resolved):
                rec = self._record_skip(logical, category, "not_present", "broken symlink -> %s" % link_target)
                rec["symlink_target"] = link_target
                return rec
            real = resolved
            try:
                st = os.stat(real)
            except OSError as exc:
                rec = self._record_skip(
                    logical, category, "skipped", "unstatable symlink target: %s" % exc, type(exc).__name__
                )
                rec["symlink_target"] = link_target
                return rec

        if statmod.S_ISDIR(st.st_mode):
            return self.collect_tree(logical, category)
        if not statmod.S_ISREG(st.st_mode):
            return self._record_skip(
                logical, category, "skipped", "unsupported file type %s" % _entry_type(st.st_mode)
            )

        archive_path = "evidence/" + logical.lstrip("/")
        stage_target = self._stage_path(archive_path)
        try:
            digest, size = _copy_hash(real, stage_target)
        except PermissionError as exc:
            return self._record_skip(logical, category, "skipped", "permission denied: %s" % exc, "PermissionError")
        except OSError as exc:
            return self._record_skip(logical, category, "skipped", str(exc), type(exc).__name__)

        try:
            shutil.copystat(real, stage_target)
        except OSError:
            try:
                os.utime(stage_target, ns=(st.st_atime_ns, st.st_mtime_ns))
            except OSError:
                pass

        rec = self._base_record(logical, category, "ok", "file", archive_path)
        rec.update(self._stat_meta(st))
        rec["type"] = "file"
        rec["sha256"] = digest
        rec["size"] = size
        rec["hashable"] = True
        if link_target is not None:
            rec["is_symlink"] = True
            rec["symlink_target"] = link_target
            rec["link_mode"] = oct(statmod.S_IMODE(st_link.st_mode))
            rec["link_mtime"] = _utc_iso(st_link.st_mtime)
        self.files.append(rec)
        self.log("INFO", "collected %s (%d bytes)" % (logical, size))
        return rec

    def _base_record(self, logical, category, status, entry_type, archive_path):
        return {
            "original_path": logical,
            "archive_path": archive_path,
            "category": category,
            "status": status,
            "type": entry_type,
            "sha256": None,
            "reason": None,
            "error_type": None,
            "hashable": archive_path is not None,
            "collected_seq": self._next_seq(),
            "collected_at": _utc_iso(),
        }

    def collect_tree(self, logical_dir, category, max_files=None):
        if max_files is None:
            max_files = self.opts.max_files_per_tree
        real_dir = self._real(logical_dir)
        collected = 0
        errors = []

        def onerror(path, exc):
            errors.append((path, exc))
            self._record_skip(
                self._logical(path),
                category,
                "skipped",
                "walk error: %s" % exc,
                type(exc).__name__,
            )

        state = {"truncated": False}
        for real_path, is_dir in walk_entries(
            real_dir, (), onerror=onerror, max_entries=max_files, state=state
        ):
            if is_dir:
                continue
            self.collect_path(self._logical(real_path), category)
            collected += 1
        if state["truncated"]:
            self.log("WARN", "tree %s truncated at %d entries" % (logical_dir, max_files))
            self.skipped.append(
                {
                    "original_path": logical_dir,
                    "category": category,
                    "status": "truncated",
                    "reason": "reached max_files_per_tree=%d" % max_files,
                }
            )
        if collected == 0 and not errors:
            self.log("INFO", "tree %s is empty" % logical_dir)
        return collected

    def expand_target(self, target, category):
        if _has_magic(target):
            if self.root == "/":
                pattern = target
            else:
                pattern = globmod.escape(self.root) + os.sep + target.lstrip("/").replace("/", os.sep)
            try:
                matches = sorted(globmod.glob(pattern))
            except OSError as exc:
                self._record_skip(target, category, "skipped", "glob error: %s" % exc, type(exc).__name__)
                return
            logicals = [self._logical(match) for match in matches]
            if not logicals:
                self._record_skip(target, category, "not_present", "not present (no glob matches)")
                return
            for logical in logicals:
                self.collect_path(logical, category)
            return
        self.collect_path(target, category)

    def _write_live(self, name, argv, category, timeout):
        result = _run(argv, timeout=timeout)
        rec = {
            "name": name,
            "argv": list(argv),
            "category": category,
            "status": result["status"],
            "exit_code": result["exit_code"],
            "seconds": result["seconds"],
            "reason": result["reason"],
            "archive_path": None,
            "sha256": None,
            "size": 0,
            "has_stderr": bool(result["stderr"]),
            "collected_seq": self._next_seq(),
            "collected_at": _utc_iso(),
        }
        if result["status"] == "not_present":
            self.live.append(rec)
            self.skipped.append(
                {"original_path": " ".join(argv), "category": category, "status": "not_present", "reason": result["reason"]}
            )
            self.log("NOT PRESENT", "%s: %s" % (name, result["reason"]))
            return rec
        payload = result["stdout"]
        if result["stderr"]:
            payload = payload + SEPARATOR + result["stderr"]
        if not payload:
            self.live.append(rec)
            self.log("INFO", "live %s produced no output" % name)
            return rec
        archive_path = "live/%s.txt" % name
        stage_target = self._stage_path(archive_path)
        _makedirs(os.path.dirname(stage_target))
        digest = hashlib.sha256()
        with open(stage_target, "wb") as handle:
            handle.write(payload)
            digest.update(payload)
        rec["archive_path"] = archive_path
        rec["sha256"] = digest.hexdigest()
        rec["size"] = len(payload)
        self.live.append(rec)
        self.log("INFO", "live %s -> %s (%d bytes, %s)" % (name, archive_path, len(payload), result["status"]))
        return rec

    def phase_live(self):
        mark = self._phase("live_state")
        if self.opts.skip_live:
            self.log("INFO", "live command collection skipped (--skip-live)")
            self._end_phase(mark)
            return
        timeout = self.opts.cmd_timeout
        for name, argv, category in LIVE_SPECS:
            cmd_timeout = self.opts.journal_timeout if name == "journalctl_export" else timeout
            self._write_live(name, argv, category, cmd_timeout)
        users = read_passwd(self.root, self.opts.max_users)
        for user in users:
            argv = ("crontab", "-l", "-u", user["name"])
            if user.get("uid") is not None:
                try:
                    if int(user["uid"]) < 0:
                        continue
                except (TypeError, ValueError):
                    pass
            result = _run(argv, timeout=timeout)
            stderr_text = result["stderr"].decode("utf-8", "replace")
            no_crontab = result["exit_code"] not in (0, None) and "no crontab" in stderr_text.lower()
            if result["status"] == "not_present" or no_crontab:
                rec = {
                    "name": "crontab_%s" % user["name"],
                    "argv": list(argv),
                    "category": "persistence",
                    "status": "not_present",
                    "exit_code": result["exit_code"],
                    "seconds": result["seconds"],
                    "reason": result["reason"] or ("no crontab for %s" % user["name"]),
                    "archive_path": None,
                    "sha256": None,
                    "size": 0,
                    "has_stderr": False,
                    "collected_seq": self._next_seq(),
                    "collected_at": _utc_iso(),
                }
                self.live.append(rec)
                self.log("NOT PRESENT", "%s: %s" % (rec["name"], rec["reason"]))
                continue
            self._write_live("crontab_%s" % user["name"], argv, "persistence", timeout)
        self._end_phase(mark)

    def phase_files(self):
        mark = self._phase("file_artifacts")
        for target, category in FILE_TARGETS:
            self.expand_target(target, category)
        users = read_passwd(self.root, self.opts.max_users)
        for user in users:
            home = user["home"]
            if not home.startswith("/"):
                continue
            home_real = self._real(home)
            if not os.path.isdir(home_real):
                self.log("INFO", "skipping user %s: home %s not present" % (user["name"], home))
                continue
            for filename, category in PER_USER_FILES:
                logical = (home.rstrip("/") + "/" + filename)
                if not os.path.lexists(self._real(logical)):
                    self._record_skip(logical, category, "not_present", "not present")
                    continue
                self.collect_path(logical, category)
        self._end_phase(mark)

    def _write_triage(self, name, header, rows, truncated=False, category="triage", status="ok"):
        archive_path = "triage/%s.txt" % name
        stage_target = self._stage_path(archive_path)
        _makedirs(os.path.dirname(stage_target))
        digest = hashlib.sha256()
        size = 0
        with open(stage_target, "w", encoding="utf-8", errors="replace", newline="\n") as handle:
            block = "\t".join(header) + "\n"
            handle.write(block)
            digest.update(block.encode("utf-8"))
            size += len(block)
            for row in rows:
                line = "\t".join(row) + "\n"
                handle.write(line)
                digest.update(line.encode("utf-8"))
                size += len(line)
        rec = {
            "name": name,
            "archive_path": archive_path,
            "status": status,
            "reason": "directory not present" if status == "not_present" else None,
            "sha256": digest.hexdigest(),
            "size": size,
            "entries": len(rows),
            "truncated": truncated,
            "category": category,
            "collected_seq": self._next_seq(),
            "collected_at": _utc_iso(),
        }
        self.triage.append(rec)
        self.log("INFO", "triage %s: %d entries (%s)" % (name, len(rows), status))
        return rec

    def phase_triage(self):
        mark = self._phase("filesystem_triage")
        if self.opts.skip_triage:
            self.log("INFO", "triage skipped (--skip-triage)")
            self._end_phase(mark)
            return
        listing_cap = self.opts.max_listing
        prunes_real = [self._real(path) for path in TRIAGE_PRUNES]
        if self.root == "/":
            prunes_real.append(self.staging)
            prunes_real.append(self.outdir)
        header = ("path", "type", "mode", "uid", "gid", "size", "mtime_utc", "ctime_utc", "atime_utc")
        for logical in LISTING_DIRS:
            rows = []
            state = {"truncated": False}

            def onerror(path, exc, _logical=logical):
                self.error_log_count += 1
                if self.error_log_count <= self.error_log_cap:
                    self._record_skip(self._logical(path), "triage", "skipped", "walk error: %s" % exc, type(exc).__name__)

            if not os.path.isdir(self._real(logical)):
                self.log("NOT PRESENT", "triage listing %s: not present" % logical)
                self._write_triage(
                    "%s_listing" % logical.strip("/").replace("/", "_"),
                    header,
                    rows,
                    False,
                    "triage_listing",
                    status="not_present",
                )
                continue

            for real_path, _is_dir in walk_entries(
                self._real(logical),
                prunes_real,
                onerror=onerror,
                max_entries=listing_cap,
                state=state,
            ):
                try:
                    st = _lstat(real_path)
                except OSError as exc:
                    onerror(real_path, exc)
                    continue
                meta = self._stat_meta(st)
                rows.append(
                    (
                        self._logical(real_path),
                        meta["type"],
                        meta["mode"],
                        str(meta["uid"]),
                        str(meta["gid"]),
                        str(meta["size"]),
                        meta["mtime"],
                        meta["ctime"],
                        meta["atime"],
                    )
                )
            rows.sort(key=lambda row: row[0])
            name = logical.strip("/").replace("/", "_")
            self._write_triage("%s_listing" % name, header, rows, state["truncated"], "triage_listing")

        suid_rows = []
        hidden_rows = []
        recent_rows = []
        state = {"truncated": False}
        cutoff = time.time() - (self.opts.recent_days * 86400)
        home_prefixes = ("/home/", "/root/")
        counts = {"suid": 0, "hidden": 0, "recent": 0}
        caps = {
            "suid": self.opts.max_suid,
            "hidden": self.opts.max_hidden,
            "recent": self.opts.max_recent,
        }

        def onerror_scan(path, exc):
            self.error_log_count += 1
            if self.error_log_count <= self.error_log_cap:
                self._record_skip(self._logical(path), "triage", "skipped", "walk error: %s" % exc, type(exc).__name__)

        for real_path, _is_dir in walk_entries(
            self._real("/"),
            prunes_real,
            onerror=onerror_scan,
            max_entries=self.opts.max_scan,
            state=state,
        ):
            try:
                st = _lstat(real_path)
            except OSError as exc:
                onerror_scan(real_path, exc)
                continue
            meta = self._stat_meta(st)
            logical = self._logical(real_path)
            if meta["suid"] or meta["sgid"]:
                counts["suid"] += 1
                if len(suid_rows) < caps["suid"]:
                    flags = "suid" if meta["suid"] and not meta["sgid"] else "sgid"
                    if meta["suid"] and meta["sgid"]:
                        flags = "suid+sgid"
                    suid_rows.append(
                        (
                            logical,
                            meta["mode"],
                            str(meta["uid"]),
                            str(meta["gid"]),
                            str(meta["size"]),
                            meta["mtime"],
                            flags,
                            meta["type"],
                        )
                    )
            name = os.path.basename(logical)
            if name.startswith(".") and name not in (".", ".."):
                if logical.startswith(home_prefixes):
                    counts["hidden"] += 1
                    if len(hidden_rows) < caps["hidden"]:
                        hidden_rows.append(
                            (
                                logical,
                                meta["type"],
                                meta["mode"],
                                str(meta["uid"]),
                                str(meta["gid"]),
                                str(meta["size"]),
                                meta["mtime"],
                            )
                        )
            if st.st_mtime >= cutoff or st.st_ctime >= cutoff:
                counts["recent"] += 1
                if len(recent_rows) < caps["recent"]:
                    recent_rows.append(
                        (
                            logical,
                            meta["type"],
                            meta["mode"],
                            str(meta["uid"]),
                            str(meta["gid"]),
                            str(meta["size"]),
                            meta["mtime"],
                            meta["ctime"],
                            meta["atime"],
                        )
                    )

        self._write_triage(
            "suid_sgid",
            ("path", "mode", "uid", "gid", "size", "mtime_utc", "flags", "type"),
            suid_rows,
            counts["suid"] > len(suid_rows),
            "suid_sgid",
        )
        self._write_triage(
            "hidden_files",
            ("path", "type", "mode", "uid", "gid", "size", "mtime_utc"),
            hidden_rows,
            counts["hidden"] > len(hidden_rows),
            "hidden_files",
        )
        recent_rows.sort(key=lambda row: row[6], reverse=True)
        self._write_triage(
            "recent_files",
            ("path", "type", "mode", "uid", "gid", "size", "mtime_utc", "ctime_utc", "atime_utc"),
            recent_rows,
            counts["recent"] > len(recent_rows),
            "recent_files",
        )
        if state["truncated"]:
            self.log("WARN", "general triage scan truncated at %d entries" % self.opts.max_scan)
        self._end_phase(mark)

    def _validate_outdir(self):
        if not self.outdir:
            raise SystemExit("error: output directory is required")
        if os.path.exists(self.outdir) and not os.path.isdir(self.outdir):
            raise SystemExit("error: output path exists and is not a directory: %s" % self.outdir)
        if self.root != "/" and _is_within(self.outdir, self.root):
            raise SystemExit(
                "error: output directory %s is inside the evidence root %s; refusing to write into evidence"
                % (self.outdir, self.root)
            )
        for logical_root in READ_ONLY_FILE_ROOTS:
            real_root = self._real(logical_root)
            if _is_within(self.outdir, real_root):
                raise SystemExit(
                    "error: output directory %s is inside evidence location %s; choose another output path"
                    % (self.outdir, logical_root)
                )

    def run(self):
        self._validate_outdir()
        _makedirs(self.outdir)
        if not os.path.isdir(self.staging):
            os.makedirs(self.staging)
        try:
            self.log("INFO", "LinuxDFIR collector %s starting" % COLLECTOR_VERSION)
            self.log("INFO", "evidence root: %s" % self.root)
            self.log("INFO", "output dir: %s" % self.outdir)
            mark = self._phase("environment")
            self.environment = detect_environment(self.root)
            self.timezone = detect_timezone(self.root)
            self.os_release = parse_os_release(self.root)
            try:
                hostname = socket.gethostname()
            except OSError:
                hostname = None
            fqdn = None
            try:
                fqdn = socket.getfqdn()
            except OSError:
                fqdn = None
            self.host_meta = {
                "hostname": hostname,
                "fqdn": fqdn,
                "hostname_file": None,
            }
            hostname_path = os.path.join(self.root, "etc", "hostname") if self.root != "/" else "/etc/hostname"
            try:
                with open(hostname_path, "r", encoding="utf-8", errors="replace") as handle:
                    self.host_meta["hostname_file"] = handle.read().strip()
            except OSError:
                pass
            if self.root != "/" and self.host_meta["hostname_file"]:
                self.host_meta["hostname"] = self.host_meta["hostname_file"]
            self.log(
                "INFO",
                "host: %s (wsl=%s, tz=%s)"
                % (self.host_meta["hostname"], self.environment.get("wsl"), self.timezone.get("name")),
            )
            self._end_phase(mark)

            self.phase_live()
            self.phase_files()
            self.phase_triage()
            return self.finalize()
        finally:
            if os.path.isdir(self.staging):
                _rmtree(self.staging)

    def finalize(self):
        self.log("INFO", "finalizing evidence archive")
        log_archive_path = "collect.log"
        log_stage = self._stage_path(log_archive_path)
        _makedirs(os.path.dirname(log_stage))
        log_payload = ("\n".join(self.log_lines) + "\n").encode("utf-8", "replace")
        with open(log_stage, "wb") as handle:
            handle.write(log_payload)
        log_digest = hashlib.sha256(log_payload).hexdigest()

        counts = {
            "files_total": len(self.files),
            "files_ok": sum(1 for rec in self.files if rec["status"] == "ok"),
            "files_not_present": sum(1 for rec in self.files if rec["status"] == "not_present"),
            "files_skipped": sum(1 for rec in self.files if rec["status"] == "skipped"),
            "live_total": len(self.live),
            "live_ok": sum(1 for rec in self.live if rec["status"] == "ok"),
            "live_not_present": sum(1 for rec in self.live if rec["status"] == "not_present"),
            "triage_total": len(self.triage),
            "hashed_entries": sum(1 for rec in self.live if rec.get("sha256"))
            + sum(1 for rec in self.triage if rec.get("sha256"))
            + sum(1 for rec in self.files if rec.get("sha256")),
            "skipped_total": len(self.skipped),
            "walk_errors": self.error_log_count,
        }
        manifest = {
            "schema": SCHEMA,
            "collector": {
                "name": "linuxdfir-collector",
                "version": COLLECTOR_VERSION,
                "script": os.path.basename(__file__),
                "python": platform.python_version(),
            },
            "hostname": self.host_meta["hostname"],
            "fqdn": self.host_meta["fqdn"],
            "hostname_file": self.host_meta["hostname_file"],
            "collection_time_utc": _utc_iso(self.started),
            "collection_start_epoch": round(self.started, 6),
            "collection_end_epoch": round(time.time(), 6),
            "duration_seconds": round(time.time() - self.started, 3),
            "running_user": running_user(),
            "kernel": dict(kernel_info(), proc_version=self.environment.get("proc_version")),
            "os": self.os_release,
            "environment": self.environment,
            "timezone": self.timezone,
            "hash_algorithm": "sha256",
            "tag": getattr(self.opts, "tag", None),
            "triage_recent_days": self.opts.recent_days,
            "triage_prunes": list(TRIAGE_PRUNES),
            "counts": counts,
            "phases": self.phases,
            "files": self.files,
            "live_commands": self.live,
            "triage": self.triage,
            "skipped": self.skipped,
            "collect_log": {
                "archive_path": log_archive_path,
                "sha256": log_digest,
                "size": len(log_payload),
            },
        }
        manifest_stage = self._stage_path("manifest.json")
        _makedirs(os.path.dirname(manifest_stage))
        manifest_payload = json.dumps(manifest, indent=2, sort_keys=False, default=str).encode("utf-8")
        with open(manifest_stage, "wb") as handle:
            handle.write(manifest_payload)

        tar_path = os.path.join(self.outdir, "evidence.tar.gz")
        self._pack(tar_path)
        tar_digest = self._hash_file(tar_path)
        sidecar = tar_path + ".sha256"
        with open(sidecar, "w", encoding="ascii") as handle:
            handle.write("%s  %s\n" % (tar_digest, os.path.basename(tar_path)))
        summary = {
            "archive": tar_path,
            "sha256": tar_digest,
            "sha256_file": sidecar,
            "manifest": manifest,
            "staging_removed": not os.path.isdir(self.staging),
        }
        print("evidence archive : %s" % tar_path)
        print("archive sha256   : %s" % tar_digest)
        print("files ok/missing/skipped: %d / %d / %d"
              % (counts["files_ok"], counts["files_not_present"], counts["files_skipped"]))
        print("live commands ok/missing: %d / %d" % (counts["live_ok"], counts["live_not_present"]))
        print("triage listings  : %d" % counts["triage_total"])
        return summary

    def _pack(self, tar_path):
        tmp_tar = tar_path + ".partial"
        entries = [("manifest.json", "manifest"), ("collect.log", "collect.log")]
        for rec in self.files:
            if rec.get("archive_path"):
                entries.append((rec["archive_path"], "file"))
        for rec in self.live:
            if rec.get("archive_path"):
                entries.append((rec["archive_path"], "live"))
        for rec in self.triage:
            if rec.get("archive_path"):
                entries.append((rec["archive_path"], "triage"))
        with tarfile.open(tmp_tar, "w:gz", compresslevel=6) as tar:
            for archive_path, _kind in entries:
                real = self._stage_path(archive_path)
                if not os.path.isfile(real):
                    continue
                tar.add(real, arcname=archive_path, recursive=False)
        os.replace(tmp_tar, tar_path)

    @staticmethod
    def _hash_file(path):
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                buf = handle.read(CHUNK)
                if not buf:
                    break
                digest.update(buf)
        return digest.hexdigest()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="linux_collector.py",
        description="LinuxDFIR Toolkit read-only forensic collector (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Output layout:\n"
            "  <outdir>/evidence.tar.gz\n"
            "  <outdir>/evidence.tar.gz.sha256\n"
            "Archive layout:\n"
            "  manifest.json   hashes, metadata, environment, timezone\n"
            "  collect.log     collector log (every skip is logged here)\n"
            "  live/*.txt      volatile command output\n"
            "  triage/*.txt    filesystem triage listings (TSV)\n"
            "  evidence/**     original absolute paths, preserved\n"
        ),
    )
    parser.add_argument("-o", "--output", required=True, help="output directory (must be writable, outside evidence)")
    parser.add_argument("--root", default="/", help="evidence root to collect from (default: /, the running system)")
    parser.add_argument("--skip-live", action="store_true", help="do not run live commands")
    parser.add_argument("--skip-triage", action="store_true", help="do not run filesystem triage walks")
    parser.add_argument("--recent-days", type=int, default=7, help="recency window in days (default: 7)")
    parser.add_argument("--max-recent", type=int, default=DEFAULT_MAX_RECENT, help="cap on recent_files rows")
    parser.add_argument("--max-suid", type=int, default=DEFAULT_MAX_SUID, help="cap on suid_sgid rows")
    parser.add_argument("--max-hidden", type=int, default=DEFAULT_MAX_HIDDEN, help="cap on hidden_files rows")
    parser.add_argument("--max-listing", type=int, default=DEFAULT_MAX_LISTING, help="cap on /tmp /var/tmp /dev/shm rows")
    parser.add_argument("--max-scan", type=int, default=DEFAULT_MAX_SCAN, help="cap on total entries in the general triage walk")
    parser.add_argument(
        "--max-files-per-tree",
        type=int,
        default=DEFAULT_MAX_FILES_PER_TREE,
        help="cap on files collected per directory tree",
    )
    parser.add_argument("--max-users", type=int, default=DEFAULT_MAX_USERS, help="cap on users processed")
    parser.add_argument("--cmd-timeout", type=int, default=DEFAULT_CMD_TIMEOUT, help="timeout per live command (seconds)")
    parser.add_argument("--journal-timeout", type=int, default=DEFAULT_JOURNAL_TIMEOUT, help="timeout for journalctl export")
    parser.add_argument("--tag", default=None, help="free-form tag recorded in the manifest")
    parser.add_argument("-v", "--verbose", action="store_true", help="log progress to stderr")
    parser.add_argument("--version", action="version", version="linuxdfir-collector %s" % COLLECTOR_VERSION)
    return parser


def main(argv=None):
    parser = build_parser()
    opts = parser.parse_args(argv)
    opts.skip_live = getattr(opts, "skip_live", False)
    opts.skip_triage = getattr(opts, "skip_triage", False)
    if opts.root not in ("/", "") and not os.path.isdir(opts.root):
        parser.error("--root %s is not a directory" % opts.root)
    collector = Collector(opts.output, root=opts.root, opts=opts)
    try:
        collector.run()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print("collector failed: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 1
    if opts.tag:
        print("tag               : %s" % opts.tag)
    print("manifest counts   : see manifest.json -> counts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
