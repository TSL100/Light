"""EXPERIMENTAL, UNTESTED remote collection over SSH.

This module is a documented stub: the interface and safety properties are
specified and enforced, but the SSH transport is intentionally not exercised
by the test suite and is not considered production-ready. Treat it as a
starting point for authorized collection from a workstation you control.

Design constraints that the implementation must keep:

* **Key authentication only.** Passwords and keyboard-interactive prompts are
  refused; nothing here ever stores, prompts for, or logs a password.
* **Strict host-key verification.** The server's host key is checked against
  ``known_hosts``. An unknown or mismatched key aborts before any transfer.
* **Explicit confirmation.** ``--confirm`` is required. Without it the run
  refuses to touch the remote host, so a mistyped hostname cannot trigger an
  unauthorized collection.
* **Read-only, bounded remote work.** The collector runs with ``sudo`` only
  when the caller asks for it, is always the read-only bash/Python collector,
  and writes only into a caller-chosen staging directory.
* **No shell interpolation.** Remote commands are built from a fixed template
  with shell-quoted arguments; user input never becomes part of a command
  string by concatenation.

Typical flow (once implemented)::

    remote = RemoteCollector(host, user="root", key_file="~/.ssh/id_ed25519")
    remote.require_confirmation("--confirm")          # fails without it
    remote.upload_collector()                          # scp the .sh/.py
    remote.run(sudo=True)                              # run read-only collector
    remote.pull(out_dir)                               # evidence.tar.gz + sidecar

Raises:
    RemoteError: on any transport, authentication, or confirmation failure.
    ImportError: if paramiko is not installed (``pip install .[remote]``).
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["RemoteError", "RemoteCollector"]

_COLLECTOR_SH = Path(__file__).resolve().parent.parent / "collector" / "linux_collector.sh"
_COLLECTOR_PY = Path(__file__).resolve().parent.parent / "collector" / "linux_collector.py"
_STAGING_DIR = "/tmp/linuxdfir-collect"


class RemoteError(RuntimeError):
    """Any remote-collection failure (auth, transport, confirmation, remote exit)."""


class RemoteCollector:
    """Drive a read-only collection on a remote Linux host over SSH.

    Args:
        host: hostname or IP of the target.
        user: SSH username.
        key_file: path to a private key. Required; passwords are not supported.
        port: SSH port (default 22).
        known_hosts: path to a known_hosts file for strict host-key checking.
            Defaults to ``~/.ssh/known_hosts``.
        timeout: per-operation socket timeout in seconds.
    """

    def __init__(
        self,
        host: str,
        user: str,
        key_file: str,
        port: int = 22,
        known_hosts: str | None = None,
        timeout: int = 60,
    ) -> None:
        if not host:
            raise RemoteError("host is required")
        if not key_file:
            raise RemoteError("key_file is required; password authentication is not supported")
        self.host = host
        self.user = user
        self.key_file = str(Path(key_file).expanduser())
        self.port = port
        self.known_hosts = str(Path(known_hosts).expanduser()) if known_hosts else str(
            Path.home() / ".ssh" / "known_hosts"
        )
        self.timeout = timeout
        self._client = None
        self._confirmed = False

    # ------------------------------------------------------------------
    # confirmation
    # ------------------------------------------------------------------
    def require_confirmation(self, flag: str | None) -> None:
        """Refuse to proceed unless the caller passed ``--confirm``.

        Call this before any network I/O. The raw argv flag is accepted so the
        CLI can forward exactly what the operator typed.
        """
        if flag != "--confirm":
            raise RemoteError(
                "remote collection refused: pass --confirm to acknowledge that you are "
                "authorized to collect from this host"
            )
        self._confirmed = True

    def _require_confirmed(self) -> None:
        if not self._confirmed:
            raise RemoteError("remote collection refused: require_confirmation() was not satisfied")

    # ------------------------------------------------------------------
    # transport (lazy paramiko import)
    # ------------------------------------------------------------------
    def _paramiko(self):
        try:
            import paramiko  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - depends on extra
            raise RemoteError(
                "paramiko is required for remote collection; install with: pip install .[remote]"
            ) from exc
        return paramiko

    def connect(self) -> None:
        """Open the SSH connection with key auth and strict host-key checking."""
        self._require_confirmed()
        if self._client is not None:
            return
        paramiko = self._paramiko()
        if not Path(self.key_file).is_file():
            raise RemoteError(f"key file not found: {self.key_file}")
        if not Path(self.known_hosts).is_file():
            raise RemoteError(
                f"known_hosts not found: {self.known_hosts}; pre-populate it so the host key "
                "can be verified (ssh-keyscan <host> >> known_hosts on a channel you trust)"
            )
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.load_host_keys(self.known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.user,
                key_filename=self.key_file,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
        except paramiko.SSHException as exc:
            raise RemoteError(f"SSH connection to {self.host} failed: {exc}") from exc
        except OSError as exc:
            raise RemoteError(f"cannot reach {self.host}:{self.port}: {exc}") from exc
        self._client = client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # ------------------------------------------------------------------
    # command execution (fixed templates, shell-quoted args)
    # ------------------------------------------------------------------
    def _run(self, command: str, timeout: int | None = None) -> tuple[int, str, str]:
        """Run a fixed-template command; returns (exit_code, stdout, stderr)."""
        self._require_confirmed()
        if self._client is None:
            raise RemoteError("not connected: call connect() first")
        _in, out, err = self._client.exec_command(command, timeout=timeout or self.timeout)
        stdout = out.read().decode("utf-8", errors="replace")
        stderr = err.read().decode("utf-8", errors="replace")
        code = out.channel.recv_exit_status()
        return code, stdout, stderr

    def _quote(self, value: str) -> str:
        import shlex  # noqa: PLC0415

        return shlex.quote(value)

    # ------------------------------------------------------------------
    # the documented workflow
    # ------------------------------------------------------------------
    def upload_collector(self) -> None:
        """Copy the collector script to the remote staging directory."""
        self.connect()
        script = _COLLECTOR_SH if _COLLECTOR_SH.is_file() else _COLLECTOR_PY
        if not script.is_file():  # pragma: no cover - repo layout guard
            raise RemoteError("no collector script found next to linuxdfir package")
        code, _out, err = self._run(f"mkdir -p {self._quote(_STAGING_DIR)} && chmod 700 {self._quote(_STAGING_DIR)}")
        if code != 0:
            raise RemoteError(f"cannot create staging dir {_STAGING_DIR}: {err.strip()}")
        sftp = self._client.open_sftp()
        try:
            sftp.put(str(script), f"{_STAGING_DIR}/{script.name}")
            sftp.chmod(f"{_STAGING_DIR}/{script.name}", 0o700)
        finally:
            sftp.close()

    def run(self, sudo: bool = False, out_dir: str = _STAGING_DIR, extra_args: list[str] | None = None) -> None:
        """Run the read-only collector on the remote host.

        Args:
            sudo: prefix the collector with ``sudo --non-interactive``.
            out_dir: remote directory for the resulting archive.
            extra_args: extra collector flags, each shell-quoted as a unit.
        """
        self.connect()
        script = _COLLECTOR_SH.name
        runner = "sudo --non-interactive " if sudo else ""
        quoted = " ".join(self._quote(a) for a in (extra_args or []))
        command = (
            f"cd {self._quote(_STAGING_DIR)} && "
            f"{runner}bash {self._quote(script)} -o {self._quote(out_dir)} --skip-live {quoted}"
        )
        code, out, err = self._run(command, timeout=600)
        if code != 0:
            raise RemoteError(f"remote collector exited {code}: {err.strip() or out.strip()}")

    def pull(self, out_dir: str | Path, name: str = "evidence.tar.gz") -> Path:
        """Download the archive plus its ``.sha256`` sidecar to ``out_dir``."""
        self._require_confirmed()
        if self._client is None:
            raise RemoteError("not connected: call connect() first")
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        sftp = self._client.open_sftp()
        try:
            remote = f"{_STAGING_DIR}/{name}"
            local = out_path / name
            try:
                sftp.get(remote, str(local))
            except OSError as exc:
                raise RemoteError(f"cannot fetch {remote}: {exc}") from exc
            try:
                sftp.get(f"{remote}.sha256", str(out_path / f"{name}.sha256"))
            except OSError:
                # sidecar is produced by the collector; its absence means the
                # remote run did not complete and must not be silently ignored.
                raise RemoteError(f"missing sidecar {remote}.sha256; remote run incomplete") from None
        finally:
            sftp.close()
        return out_path / name

    def __enter__(self) -> RemoteCollector:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def _default_confirm_from_env() -> bool:
    """True only when the operator exported LINUXDFIR_REMOTE_CONFIRM=1."""
    return os.environ.get("LINUXDFIR_REMOTE_CONFIRM") == "1"
