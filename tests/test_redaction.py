"""Secret redaction: central (Event construction) + byte-scan of all outputs.

Every output file of `run` is byte-scanned for crypt-hash prefixes and
the planted secrets; any match fails the test. Per-file match counts are
collected so the failure message shows exactly where a leak sits.
"""

from __future__ import annotations

import hashlib

from conftest import make_mini_evidence

from linuxdfir import cli
from linuxdfir.redact import redact_secrets
from linuxdfir.schema import Event

SHADOW6 = "$6$testrounds$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
SHADOW1 = "$1$salt1234$abcdefghijklmnopqrstuvwxyzABCD"
SHADOW5 = "$5$salt1234$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"
BCRYPT = "$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL0123456"
YESCRYPT = "$y$j9T$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO0123"
PW1 = "s3cr3t-pw-1"
PW2 = "s3cr3t-pw-2"
TOKEN = "tok_abc123XYZ"


def _fp(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()[:8]


def _ev(**kw) -> Event:
    defaults = dict(
        timestamp_utc=None,
        host="h",
        user=None,
        source_artifact="t",
        event_type="t",
        message="",
        evidence_path="/t",
    )
    defaults.update(kw)
    return Event(**defaults)


class TestRedactUnits:
    def test_crypt_hashes_keep_fields(self):
        line = f"admin:{SHADOW6}:20000:0:99999:7:::"
        out = redact_secrets(line)
        assert SHADOW6 not in out
        assert out == f"admin:[REDACTED-SHA512CRYPT:{_fp(SHADOW6)}]:20000:0:99999:7:::"

    def test_crypt_variants(self):
        assert "[REDACTED-MD5CRYPT:" in redact_secrets(f"x:{SHADOW1}:1")
        assert "[REDACTED-SHA256CRYPT:" in redact_secrets(f"x:{SHADOW5}:1")
        assert "[REDACTED-BCRYPT:" in redact_secrets(f"x:{BCRYPT}:1")
        assert "[REDACTED-YESCRYPT:" in redact_secrets(f"x:{YESCRYPT}:1")

    def test_locked_shadow_markers_untouched(self):
        assert redact_secrets("root:!:20000") == "root:!:20000"
        assert redact_secrets("daemon:*:20000") == "daemon:*:20000"

    def test_sshpass(self):
        out = redact_secrets(f"sshpass -p {PW1} ssh root@host")
        assert PW1 not in out and "sshpass -p" in out
        out = redact_secrets(f"sshpass -p{PW1} ssh root@host")
        assert PW1 not in out
        out = redact_secrets("sshpass --port 22 ssh root@host")
        assert out == "sshpass --port 22 ssh root@host"

    def test_password_flags(self):
        out = redact_secrets(f"deploy --password={PW1}")
        assert PW1 not in out and "--password=" in out
        out = redact_secrets(f"mysqldump --passwd {PW1} db")
        assert PW1 not in out
        out = redact_secrets(f"run --password '{PW1} with space'")
        assert PW1 not in out

    def test_mysql_attached_only(self):
        out = redact_secrets(f"mysql -h db -u root -p{PW1} -e 'show dbs'")
        assert PW1 not in out
        assert redact_secrets("mysql -h db -u root -p") == "mysql -h db -u root -p"

    def test_curl_user(self):
        out = redact_secrets(f"curl -u admin:{PW1} https://internal/api")
        assert PW1 not in out and "admin:" in out

    def test_bearer_and_basic(self):
        out = redact_secrets(f"GET /api x Authorization: Bearer {TOKEN}")
        assert TOKEN not in out and "Bearer" in out
        out = redact_secrets("Authorization: Basic dXNlcjpwYXNz")
        assert "dXNlcjpwYXNz" not in out

    def test_url_credentials(self):
        out = redact_secrets(f"git clone https://deploy:{PW1}@githost/repo.git")
        assert PW1 not in out and "deploy:" in out and "@githost" in out

    def test_query_params(self):
        out = redact_secrets(f"GET /login?user=admin&password={PW1} HTTP/1.1")
        assert PW1 not in out and "password=" in out
        out = redact_secrets(f"GET /api?api_key={TOKEN} HTTP/1.1")
        assert TOKEN not in out

    def test_fingerprint_stable_and_correlatable(self):
        first = redact_secrets(f"--password={PW1}")
        second = redact_secrets(f"mysql -h x -p{PW1}")
        assert first.split(":")[-1].rstrip("]") == second.split(":")[-1].rstrip("]")
        assert PW1 not in first + second

    def test_idempotent(self):
        once = redact_secrets(f"admin:{SHADOW6}:1 --password={PW1}")
        assert redact_secrets(once) == once

    def test_benign_untouched(self):
        line = "ls -la /var/log/ | grep $HOME && echo done"
        assert redact_secrets(line) == line

    def test_event_construction_redacts(self):
        event = _ev(message=f"curl -u admin:{PW1} x", raw=f"line --password={PW2}")
        assert PW1 not in event.message and PW2 not in event.raw


SECRET_FILES = {
    "/etc/shadow": (
        f"root:!:20000:0:99999:7:::\nadmin:{SHADOW6}:20000:0:99999:7:::\n"
        f"bob:{SHADOW1}:20000:0:99999:7:::\ncarol:{BCRYPT}:20000:0:99999:7:::\n"
    ).encode(),
    "/root/.bash_history": (
        f"curl -u admin:{PW1} https://internal/api\n"
        f"sshpass -p {PW2} ssh root@db\n"
        "mysql -h db -u root -pmysql-pw-3 -e 'show dbs'\n"
        "deploy --password=deploy-pw-4\n"
        "git clone https://deploy:url-pw-5@githost/repo.git\n"
    ).encode(),
    "/home/alice/.bash_history": (b"echo hello\n"),
    "/etc/ssh/sshd_config": b"PasswordAuthentication yes\n",
    "/var/log/nginx/access.log": (
        '10.0.0.7 - - [02/Jan/2026:09:15:02 +0200] '
        f'"GET /login?user=admin&password=web-pw-6 HTTP/1.1" 200 10 "-" "agent Bearer {TOKEN}"\n'
    ).encode(),
    "/var/log/auth.log": b"Jan  2 09:14:22 web01 sshd[1]: Accepted publickey for admin\n",
    "/var/log/dpkg.log": b"2026-01-02 06:25:01 startup archives unpack\n",
    "live/ps_auxf.txt": (
        b"USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
        b"root 1 0.0 0.1 166484 11832 ? Ss Jan01 0:04 /sbin/init\n"
        b"root 99 0.0 0.0 11512 3400 ? Ss 03:12 0:00 backup --passwd proc-pw-7 --target /srv\n"
    ),
}

NEEDLES = [
    SHADOW6.encode(),
    SHADOW1.encode(),
    SHADOW5.encode(),
    BCRYPT.encode(),
    YESCRYPT.encode(),
    b"$1$salt1234$",
    b"$2b$12$",
    b"$5$salt1234$",
    b"$6$testrounds$",
    b"$y$j9T$",
    PW1.encode(),
    PW2.encode(),
    b"mysql-pw-3",
    b"deploy-pw-4",
    b"url-pw-5",
    b"web-pw-6",
    b"proc-pw-7",
    TOKEN.encode(),
    b"Bearer " + TOKEN.encode(),
]

OUTPUT_FILES = [
    "events.jsonl",
    "timeline.db",
    "timeline.csv",
    "findings.json",
    "findings.csv",
    "report.html",
    "parse_stats.json",
    "verify_report.json",
]


def _scan(outdir) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in OUTPUT_FILES:
        blob = (outdir / name).read_bytes()
        counts[name] = sum(blob.count(needle) for needle in NEEDLES)
    return counts


def test_run_outputs_contain_no_secrets(tmp_path, capsys):
    root = make_mini_evidence(tmp_path / "mini", files=dict(SECRET_FILES))
    out = tmp_path / "case"
    cli.main(["verify", str(root), "--report-dir", str(out)])
    assert cli.main(["parse", str(root), "-o", str(out)]) == 0
    assert cli.main(["detect", str(out), "-o", str(out)]) == 0
    assert cli.main(["report", str(out), "--report-name", "report.html"]) == 0
    counts = _scan(out)
    with capsys.disabled():
        for name in OUTPUT_FILES:
            print(f"scan {name}: {counts[name]} matches")
    assert counts == dict.fromkeys(OUTPUT_FILES, 0), f"secret leak: {counts}"
