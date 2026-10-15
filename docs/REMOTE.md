# Remote collection (experimental)

`linuxdfir.remote` is an **experimental, untested** SSH helper for pushing the
read-only collector to a remote Linux host and pulling the archive back. The
interface and the safety rules below are enforced in code; the transport itself
is **not** covered by the test suite. Do not rely on it for production
incident response without first testing it yourself against a host you own.

## Requirements

```bash
pip install .[remote]     # installs paramiko
```

Remote side needs: `bash`, `python3`, `sha256sum`, `stat`, and (for
privileged artifacts) a working `sudo` if you pass `sudo=True`.

## Safety rules (enforced, not advisory)

| Rule | Where |
| --- | --- |
| `--confirm` is required before any network I/O | `RemoteCollector.require_confirmation()` |
| Key authentication only; passwords/agents are refused | `connect()` (`allow_agent=False`, `look_for_keys=False`) |
| Strict host-key checking; unknown/mismatched keys abort | `RejectPolicy()` + `known_hosts` |
| Host key must exist before connecting | `connect()` refuses a missing `known_hosts` |
| Remote commands use fixed templates with `shlex.quote`d args | `_run()` / `run()` |
| Collector is read-only and runs with `--skip-live` | `run()` |
| Staging dir is `chmod 700` and under `/tmp` | `upload_collector()` |

Nothing in this module stores, prompts for, or logs a password.

## Workflow

```python
from linuxdfir.remote import RemoteCollector, RemoteError

try:
    with RemoteCollector(
        "host.example.com",
        user="root",
        key_file="~/.ssh/id_ed25519",
        known_hosts="~/.ssh/known_hosts",
    ) as remote:
        remote.require_confirmation("--confirm")   # refuses without it
        remote.upload_collector()                  # scp the collector
        remote.run(sudo=True)                      # read-only, --skip-live
        archive = remote.pull("./evidence")        # evidence.tar.gz + sidecar
except RemoteError as exc:
    print(f"remote collection failed: {exc}")
```

Then analyze locally as usual:

```bash
linuxdfir run ./evidence/evidence.tar.gz -o ./analysis
```

## Populate known_hosts first

Verify the host key out-of-band (console, or a channel you already trust):

```bash
ssh-keyscan host.example.com >> ~/.ssh/known_hosts
```

Do not skip this. `RejectPolicy()` will abort on an unknown key by design.

## Risks and limitations

- **Authorization.** You are responsible for having explicit, documented
  authorization to collect from the target. `--confirm` exists only to make
  accidental runs unlikely; it is not a permission check.
- **Sensitivity.** Everything the collector reads leaves the host. Evidence
  may contain credentials, keys, and personal data — see `scan-secrets` and
  treat the archive as confidential.
- **Detection.** Remote execution, `sudo`, and bulk file reads are noisy and
  may trigger EDR/IDS alerts. Coordinate with the host owner.
- **Privileges.** Without `sudo` the collector sees only what the SSH user can
  read, and the manifest will record the misses as `not_present`.
- **Integrity.** Transport integrity comes from SSH and the local `.sha256`
  sidecar; the sidecar is checked by `linuxdfir verify` after `pull()`.
- **Maturity.** No automated test covers the SSH path. Expect rough edges.

## What is deliberately not here

- No password or interactive authentication.
- No automatic `known_hosts` trust-on-first-use.
- No command construction from raw user input.
- No persistence, agent, or anything that stays behind on the target.
