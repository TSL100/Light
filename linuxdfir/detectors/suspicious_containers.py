"""Unusual or privileged containers from docker ps snapshots.

Images whose repository name (before the first ``:`` or ``/``) is
outside the configured allowlist raise an aggregated MEDIUM finding;
rows that reference the docker socket or ``--privileged`` escalate to
HIGH (host takeover from inside a container). Routine distro and
workload images (nginx, redis, postgres, ...) are allowlisted via
detection.toml [containers].
"""

from __future__ import annotations

from collections.abc import Iterable

from ..config import load_config
from ..parsers.live_state import parse_container_message
from ..schema import Event, Finding, Ref, Severity, make_finding_id

RULE = "suspicious_containers"

USES_CONFIG = True

RULE_INFO = {
    RULE: {
        "why": (
            "Containers escape to the host via privileged mode or the docker socket; "
            "an image that is not part of the known workload inventory is a staging "
            "or cryptomining risk."
        ),
        "next_steps": [
            "Inspect the container image digest and its source registry.",
            "Check for privileged flags, docker.sock mounts and host-network mode.",
            "Review container logs and restart policies for persistence.",
            "Remove unauthorized containers and restrict docker socket access.",
        ],
    },
}

PRIVILEGED_MARKERS = ("docker.sock", "--privileged", "--pid=host", "--network=host")


def _image_name(image: str) -> str:
    name = image.split(":", 1)[0]
    return name.split("/", 1)[-1].lower()


def detect(events: Iterable[Event], config: dict | None = None) -> list[Finding]:
    cfg = config if config is not None else load_config()
    allowlist = {
        _image_name(image)
        for image in cfg.get("containers", {}).get("allowlist_images", [])
    }
    unknown: list[Event] = []
    unknown_rows: dict[str, str] = {}
    privileged: list[Event] = []
    privileged_rows: dict[str, str] = {}
    for event in events:
        if event.event_type != "container_row":
            continue
        fields = parse_container_message(event.message)
        if fields is None:
            continue
        image = fields.get("image", "")
        row = fields.get("row", event.message)
        if any(marker in row for marker in PRIVILEGED_MARKERS):
            privileged.append(event)
            privileged_rows[fields.get("id", "?")] = f"{image} {row}"
            continue
        if _image_name(image) in allowlist:
            continue
        unknown.append(event)
        unknown_rows[fields.get("id", "?")] = f"{image} names={fields.get('names', '-')}"
    findings: list[Finding] = []
    if privileged:
        names = "; ".join(f"{cid}: {row}" for cid, row in sorted(privileged_rows.items()))
        findings.append(
            Finding(
                id=make_finding_id(RULE, "privileged", names[:200]),
                rule=RULE,
                severity=Severity.HIGH,
                title=f"Privileged/host-access container ({len(privileged)})",
                description=(
                    f"{len(privileged)} container row(s) expose host-level access "
                    f"(docker.sock, --privileged, host pid/network): {names}. Any "
                    "process inside such a container can take over the host."
                ),
                mitre_ids=["T1610"],
                first_seen=privileged[0].timestamp_utc,
                count=len(privileged),
                refs=[Ref(ev.evidence_path, ev.line_or_offset) for ev in privileged[:5]],
            )
        )
    if unknown:
        names = "; ".join(f"{cid}: {row}" for cid, row in sorted(unknown_rows.items()))
        findings.append(
            Finding(
                id=make_finding_id(RULE, "unknown", names[:200]),
                rule=RULE,
                severity=Severity.MEDIUM,
                title=f"Unknown container images ({len(unknown)})",
                description=(
                    f"{len(unknown)} running container(s) use images outside the "
                    f"configured allowlist: {names}. Verify provenance; unauthorized "
                    "images often host cryptominers or reverse shells."
                ),
                mitre_ids=["T1610"],
                first_seen=unknown[0].timestamp_utc,
                count=len(unknown),
                refs=[Ref(ev.evidence_path, ev.line_or_offset) for ev in unknown[:5]],
            )
        )
    return findings
