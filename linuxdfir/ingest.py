"""Evidence ingest: open archives or folders safely, verify integrity, expose context.

The archive is treated as UNTRUSTED: members are only ever read in memory,
never extracted to disk. Absolute paths, ``..`` components and links escaping
the archive root are rejected up front with UnsafeArchiveError.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import tarfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .schema import Finding, Ref, Severity, make_finding_id

CHUNK = 1024 * 1024
GZIP_MAGIC = b"\x1f\x8b"
SIDECAR_RE = re.compile(r"^[0-9a-fA-F]{64}$")
DRIVE_RE = re.compile(r"^[A-Za-z]:")

RULE_INFO = {
    "evidence_integrity": {
        "why": (
            "A hash mismatch, missing file or unlisted file means the evidence changed after "
            "collection (or was tampered with in transit). Findings built on altered evidence "
            "cannot be trusted until integrity is re-established."
        ),
        "next_steps": [
            "Re-acquire the evidence from the source host if possible.",
            "Compare the archive SHA256 sidecar against the value recorded at collection time.",
            "Treat every downstream finding from this bundle as UNRELIABLE until resolved.",
        ],
    },
}


class UnsafeArchiveError(ValueError):
    """Raised when an evidence container holds unsafe member names or links."""


class EvidenceError(Exception):
    """Raised when evidence cannot be opened, read, or understood."""


def resolve_tzinfo(timezone_name: str | None, utc_offset_seconds: int | None):
    """Resolve manifest timezone info to a tzinfo plus provenance tag.

    Prefers the IANA name (via zoneinfo, backed by the tzdata package on
    Windows) so DST transitions are handled. Falls back to the fixed manifest
    offset only when the name is absent or unresolvable, and to UTC last.
    """
    if timezone_name:
        try:
            return ZoneInfo(timezone_name), "iana"
        except (ZoneInfoNotFoundError, ValueError):
            pass
    if utc_offset_seconds is not None:
        try:
            return timezone(timedelta(seconds=int(utc_offset_seconds))), "fixed_offset"
        except (TypeError, ValueError):
            pass
    return UTC, "utc"


@dataclass
class EvidenceContext:
    hostname: str | None
    collection_time_utc: datetime
    timezone_name: str | None
    utc_offset_seconds: int | None
    environment: dict = field(default_factory=dict)
    os_info: dict | None = None
    kernel: dict = field(default_factory=dict)
    running_user: dict = field(default_factory=dict)
    tag: str | None = None


def _check_member_name(name: str) -> None:
    if not name or name.startswith("/") or DRIVE_RE.match(name):
        raise UnsafeArchiveError(f"absolute member path rejected: {name!r}")
    if ".." in name.split("/"):
        raise UnsafeArchiveError(f"parent-directory member path rejected: {name!r}")


def _check_link_target(name: str, target: str) -> None:
    if not target or target.startswith("/") or DRIVE_RE.match(target):
        raise UnsafeArchiveError(f"link {name!r} escapes archive (absolute target)")
    if ".." in target.split("/"):
        raise UnsafeArchiveError(f"link {name!r} escapes archive (.. target)")


class Evidence:
    def __init__(self, source: str | Path, *, _tar: tarfile.TarFile | None, kind: str):
        self.source = Path(source)
        self.kind = kind
        self._tar = _tar
        self._root: Path | None = None
        if kind == "archive":
            assert _tar is not None
            self._members = sorted(m.name for m in _tar.getmembers() if m.isfile())
        else:
            self._root = self.source
            self._members = sorted(
                path.relative_to(self._root).as_posix()
                for path in sorted(self._root.rglob("*"))
                if path.is_file()
            )
        self.manifest: dict = self._load_manifest()
        self.context = self._build_context()
        self.tzinfo, self.tz_source = resolve_tzinfo(
            self.context.timezone_name, self.context.utc_offset_seconds
        )
        self.archive_to_original = {
            rec["archive_path"]: rec["original_path"]
            for rec in self.manifest.get("files", [])
            if rec.get("archive_path")
        }
        self.verify_report: dict | None = None
        self.integrity_findings: list[Finding] = []
        self.integrity_ok: bool | None = None

    @classmethod
    def open(cls, source: str | Path) -> Evidence:
        path = Path(source)
        if path.is_file():
            try:
                tar = tarfile.open(path, "r:*")
            except (tarfile.TarError, OSError) as exc:
                raise EvidenceError(f"cannot open archive {path}: {exc}") from exc
            try:
                for member in tar.getmembers():
                    _check_member_name(member.name)
                    if member.issym() or member.islnk():
                        _check_link_target(member.name, member.linkname)
            except UnsafeArchiveError:
                tar.close()
                raise
            return cls(path, _tar=tar, kind="archive")
        if path.is_dir():
            return cls(path, _tar=None, kind="folder")
        raise EvidenceError(f"evidence path is neither a file nor a directory: {path}")

    def close(self) -> None:
        if self._tar is not None:
            self._tar.close()
            self._tar = None

    def __enter__(self) -> Evidence:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    @property
    def members(self) -> list[str]:
        return list(self._members)

    def _load_manifest(self) -> dict:
        try:
            raw = self.read_bytes("manifest.json")
        except EvidenceError as exc:
            raise EvidenceError(f"manifest.json unreadable in {self.source}: {exc}") from exc
        try:
            manifest = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"manifest.json is not valid JSON in {self.source}: {exc}") from exc
        if not isinstance(manifest, dict) or "files" not in manifest:
            raise EvidenceError(f"manifest.json has no files[] section in {self.source}")
        return manifest

    def _build_context(self) -> EvidenceContext:
        manifest = self.manifest
        tz = manifest.get("timezone") or {}
        try:
            collected = datetime.fromisoformat(manifest["collection_time_utc"])
        except (KeyError, ValueError) as exc:
            raise EvidenceError(f"manifest has no usable collection_time_utc: {exc}") from exc
        if collected.tzinfo is None:
            collected = collected.replace(tzinfo=UTC)
        return EvidenceContext(
            hostname=manifest.get("hostname"),
            collection_time_utc=collected,
            timezone_name=tz.get("name"),
            utc_offset_seconds=tz.get("utc_offset_seconds"),
            environment=manifest.get("environment") or {},
            os_info=manifest.get("os"),
            kernel=manifest.get("kernel") or {},
            running_user=manifest.get("running_user") or {},
            tag=manifest.get("tag"),
        )

    def read_bytes(self, member: str) -> bytes:
        if self.kind == "archive":
            assert self._tar is not None
            try:
                info = self._tar.getmember(member)
            except KeyError:
                raise EvidenceError(f"member not in archive: {member}") from None
            if not info.isfile():
                raise EvidenceError(f"member is not a regular file: {member}")
            handle = self._tar.extractfile(info)
            if handle is None:
                raise EvidenceError(f"member unreadable: {member}")
            return handle.read()
        assert self._root is not None
        target = (self._root / member).resolve()
        if target != self._root.resolve() and self._root.resolve() not in target.parents:
            raise UnsafeArchiveError(f"member escapes evidence root: {member}")
        try:
            return target.read_bytes()
        except OSError as exc:
            raise EvidenceError(f"member unreadable: {member}: {exc}") from exc

    def iter_lines(self, member: str) -> Iterator[tuple[int, str]]:
        data = self.read_bytes(member)
        if data[:2] == GZIP_MAGIC:
            try:
                data = gzip.decompress(data)
            except OSError as exc:
                raise EvidenceError(f"member is not valid gzip: {member}: {exc}") from exc
        text = data.decode("utf-8", errors="replace")
        yield from enumerate(text.splitlines(), start=1)

    def display_path(self, member: str) -> str:
        return self.archive_to_original.get(member, member)

    def record_for_member(self, member: str) -> dict | None:
        for section in ("files", "live_commands", "triage"):
            for rec in self.manifest.get(section, []):
                if rec.get("archive_path") == member:
                    return rec
        if member == (self.manifest.get("collect_log") or {}).get("archive_path"):
            return self.manifest["collect_log"]
        return None

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def _check_sidecar(self) -> dict:
        if self.kind != "archive":
            return {"status": "not_applicable", "expected": None, "actual": None}
        sidecar = Path(str(self.source) + ".sha256")
        if not sidecar.is_file():
            return {"status": "missing", "expected": None, "actual": None}
        try:
            token = sidecar.read_text(encoding="ascii", errors="replace").split()[0]
        except (OSError, IndexError):
            token = ""
        if not SIDECAR_RE.match(token):
            return {"status": "malformed", "expected": token or None, "actual": None}
        actual = self._sha256_file(self.source)
        if actual.lower() != token.lower():
            return {"status": "mismatch", "expected": token.lower(), "actual": actual}
        return {"status": "ok", "expected": token.lower(), "actual": actual}

    def verify(self) -> dict:
        entries: list[dict] = []

        def add(kind: str, name: str, archive_path: str | None, expected: str | None) -> None:
            entries.append({"kind": kind, "name": name, "archive_path": archive_path, "expected_sha256": expected})

        for rec in self.manifest.get("files", []):
            add("file", rec.get("original_path", "?"), rec.get("archive_path"), rec.get("sha256"))
        for rec in self.manifest.get("live_commands", []):
            add("live", rec.get("name", "?"), rec.get("archive_path"), rec.get("sha256"))
        for rec in self.manifest.get("triage", []):
            add("triage", rec.get("name", "?"), rec.get("archive_path"), rec.get("sha256"))
        collect_log = self.manifest.get("collect_log") or {}
        if collect_log.get("archive_path"):
            add("collect_log", "collect.log", collect_log.get("archive_path"), collect_log.get("sha256"))

        member_set = set(self._members)
        referenced = {entry["archive_path"] for entry in entries if entry["archive_path"]}
        results: list[dict] = []
        buckets: dict[str, list[str]] = {"ok": [], "mismatch": [], "missing": [], "extra": [], "metadata_only": []}
        for entry in entries:
            expected = entry["expected_sha256"]
            archive_path = entry["archive_path"]
            result = dict(entry)
            result["actual_sha256"] = None
            if expected is None:
                result["status"] = "metadata_only"
                buckets["metadata_only"].append(archive_path or entry["name"])
            elif not archive_path or archive_path not in member_set:
                result["status"] = "missing"
                buckets["missing"].append(archive_path or entry["name"])
            else:
                actual = hashlib.sha256(self.read_bytes(archive_path)).hexdigest()
                result["actual_sha256"] = actual
                if actual.lower() == expected.lower():
                    result["status"] = "ok"
                    buckets["ok"].append(archive_path)
                else:
                    result["status"] = "mismatch"
                    buckets["mismatch"].append(archive_path)
            results.append(result)

        extra = sorted(member for member in self._members if member != "manifest.json" and member not in referenced)
        buckets["extra"].extend(extra)

        sidecar = self._check_sidecar()
        integrity_ok = not buckets["mismatch"] and not buckets["missing"] and not extra
        integrity_ok = bool(integrity_ok and sidecar["status"] in ("ok", "not_applicable"))

        findings: list[Finding] = []
        for entry in results:
            if entry["status"] == "mismatch":
                findings.append(
                    Finding(
                        id=make_finding_id("evidence_integrity", "mismatch", entry["archive_path"]),
                        rule="evidence_integrity",
                        severity=Severity.HIGH,
                        title=f"Hash mismatch: {entry['archive_path']}",
                        description=(
                            f"manifest expects sha256 {entry['expected_sha256']} "
                            f"but the archive holds {entry['actual_sha256']}"
                        ),
                        refs=[Ref("manifest.json", None)],
                    )
                )
            elif entry["status"] == "missing":
                findings.append(
                    Finding(
                        id=make_finding_id("evidence_integrity", "missing", entry["archive_path"]),
                        rule="evidence_integrity",
                        severity=Severity.HIGH,
                        title=f"Missing from archive: {entry['archive_path']}",
                        description="listed in manifest.json but absent from the evidence container",
                        refs=[Ref("manifest.json", None)],
                    )
                )
        for member in extra:
            findings.append(
                Finding(
                    id=make_finding_id("evidence_integrity", "extra", member),
                    rule="evidence_integrity",
                    severity=Severity.HIGH,
                    title=f"Not in manifest: {member}",
                    description="present in the evidence container but absent from manifest.json",
                    refs=[Ref("manifest.json", None)],
                )
            )
        if sidecar["status"] == "mismatch":
            findings.append(
                Finding(
                    id=make_finding_id("evidence_integrity", "sidecar", "mismatch"),
                    rule="evidence_integrity",
                    severity=Severity.HIGH,
                    title="Archive sidecar mismatch",
                    description=(
                        f"sidecar expects {sidecar['expected']} but the archive hashes to {sidecar['actual']}"
                    ),
                    refs=[Ref("manifest.json", None)],
                )
            )
        elif sidecar["status"] in ("missing", "malformed"):
            findings.append(
                Finding(
                    id=make_finding_id("evidence_integrity", "sidecar", sidecar["status"]),
                    rule="evidence_integrity",
                    severity=Severity.MEDIUM,
                    title=f"Archive sidecar {sidecar['status']}",
                    description="archive transport integrity cannot be confirmed without a valid sidecar file",
                    refs=[Ref("manifest.json", None)],
                )
            )

        report = {
            "source": str(self.source),
            "kind": self.kind,
            "manifest_schema": self.manifest.get("schema"),
            "hostname": self.context.hostname,
            "collection_time_utc": self.manifest.get("collection_time_utc"),
            "sidecar": sidecar,
            "results": results,
            "ok": buckets["ok"],
            "mismatch": buckets["mismatch"],
            "missing": buckets["missing"],
            "extra": buckets["extra"],
            "metadata_only": buckets["metadata_only"],
            "counts": {key: len(value) for key, value in buckets.items()},
            "integrity_ok": integrity_ok,
        }
        self.verify_report = report
        self.integrity_findings = findings
        self.integrity_ok = integrity_ok
        return report
