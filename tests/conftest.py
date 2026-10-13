import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATE_PATH = REPO_ROOT / "sample_evidence" / "generate.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def load_generate():
    spec = importlib.util.spec_from_file_location("sample_generate", GENERATE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def generated(tmp_path_factory):
    module = load_generate()
    out = tmp_path_factory.mktemp("sample")
    results = module.generate_all(str(out), seed=1337)
    return {"gen": module, "results": results}


def make_mini_evidence(
    root, *, tz_name="Africa/Cairo", tz_offset=7200, files=None, collection_time_utc="2026-01-03T06:00:00Z"
):
    """Build a minimal evidence folder keyed by ORIGINAL artifact path."""
    root = Path(root)
    blobs = {"/etc/hostname": b"mini\n"}
    if files:
        blobs.update(files)
    records = []
    for original_path, data in blobs.items():
        archive_path = "evidence/" + original_path.lstrip("/")
        target = root / Path(*archive_path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        records.append(
            {
                "original_path": original_path,
                "archive_path": archive_path,
                "category": "test",
                "status": "ok",
                "type": "file",
                "sha256": hashlib.sha256(data).hexdigest(),
                "hashable": True,
            }
        )
    log = b"mini collect log\n"
    (root / "collect.log").write_bytes(log)
    manifest = {
        "schema": "linuxdfir/collector-manifest/1",
        "hostname": "mini",
        "collection_time_utc": collection_time_utc,
        "running_user": {},
        "kernel": {},
        "os": None,
        "environment": {},
        "timezone": {
            "name": tz_name,
            "source": "test",
            "utc_offset_seconds": tz_offset,
            "utc_offset_str": None,
            "tz_env": None,
            "tzname": [],
        },
        "hash_algorithm": "sha256",
        "counts": {},
        "phases": [],
        "files": records,
        "live_commands": [],
        "triage": [],
        "skipped": [],
        "collect_log": {
            "archive_path": "collect.log",
            "sha256": hashlib.sha256(log).hexdigest(),
            "size": len(log),
        },
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return root
