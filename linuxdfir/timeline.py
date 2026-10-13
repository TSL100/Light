"""Unified timeline: SQLite-backed event store with sorted merge and queries.

Events stream from every parser into a SQLite database next to events.jsonl,
so large evidence never lives in RAM. Dated events merge-sort by timestamp
(stable on artifact, then line); undated events stay in their own group with
no invented timestamps. Only exact duplicates (same artifact, path, line,
type, message and timestamp, e.g. a file collected twice) are dropped.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .schema import Event, Finding

EARLIEST_SANE = datetime(2000, 1, 1, tzinfo=UTC)
SKEW_TOLERANCE = timedelta(days=1)
BATCH_SIZE = 2000

ORDER_BY = (
    "timestamp_utc ASC, source_artifact ASC, evidence_path ASC, "
    "COALESCE(line_int, 9223372036854775807) ASC, line_raw ASC, id ASC"
)
UNDATED_ORDER_BY = (
    "source_artifact ASC, evidence_path ASC, "
    "COALESCE(line_int, 9223372036854775807) ASC, line_raw ASC, id ASC"
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT,
    timestamp_quality TEXT NOT NULL,
    suspicious_time INTEGER NOT NULL DEFAULT 0,
    host TEXT,
    user TEXT,
    source_artifact TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    evidence_path TEXT NOT NULL,
    line_int INTEGER,
    line_raw TEXT,
    raw TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    mitre_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL DEFAULT 1.0,
    parser TEXT NOT NULL DEFAULT '',
    repeat_count INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup ON events(
    source_artifact, evidence_path, COALESCE(line_raw, ''),
    event_type, message, COALESCE(timestamp_utc, '')
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_artifact ON events(source_artifact);
"""

INSERT_SQL = """
INSERT OR IGNORE INTO events(
    timestamp_utc, timestamp_quality, suspicious_time, host, user,
    source_artifact, event_type, message, evidence_path, line_int, line_raw,
    raw, tags_json, mitre_json, confidence, parser, repeat_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

CSV_HEADER = [
    "timestamp_utc",
    "timestamp_quality",
    "suspicious_time",
    "host",
    "user",
    "source_artifact",
    "event_type",
    "message",
    "evidence_path",
    "line_or_offset",
    "tags",
    "mitre_ids",
    "confidence",
    "parser",
    "repeat_count",
]


def _line_parts(line_or_offset) -> tuple:
    if isinstance(line_or_offset, bool):
        return None, str(line_or_offset)
    if isinstance(line_or_offset, int):
        return line_or_offset, str(line_or_offset)
    if line_or_offset is None:
        return None, None
    return None, str(line_or_offset)


def _is_suspicious(stamp: datetime | None, collection_time_utc: datetime) -> int:
    if stamp is None:
        return 0
    if stamp < EARLIEST_SANE or stamp > collection_time_utc + SKEW_TOLERANCE:
        return 1
    return 0


def _event_to_row(event: Event, collection_time_utc: datetime) -> tuple:
    data = event.to_dict()
    line_int, line_raw = _line_parts(event.line_or_offset)
    return (
        data["timestamp_utc"],
        data["timestamp_quality"],
        _is_suspicious(event.timestamp_utc, collection_time_utc),
        data["host"],
        data["user"],
        data["source_artifact"],
        data["event_type"],
        data["message"],
        data["evidence_path"],
        line_int,
        line_raw,
        data["raw"],
        json.dumps(data["tags"]),
        json.dumps(data["mitre_ids"]),
        data["confidence"],
        data["parser"],
        data["repeat_count"],
    )


def _row_to_event(row: sqlite3.Row) -> Event:
    line = row["line_int"] if row["line_int"] is not None else row["line_raw"]
    return Event(
        timestamp_utc=datetime.fromisoformat(row["timestamp_utc"]) if row["timestamp_utc"] else None,
        timestamp_quality=row["timestamp_quality"],
        host=row["host"],
        user=row["user"],
        source_artifact=row["source_artifact"],
        event_type=row["event_type"],
        message=row["message"],
        evidence_path=row["evidence_path"],
        line_or_offset=line,
        raw=row["raw"],
        tags=json.loads(row["tags_json"]),
        mitre_ids=json.loads(row["mitre_json"]),
        confidence=row["confidence"],
        parser=row["parser"],
        repeat_count=row["repeat_count"],
    )


def _row_to_json(row: sqlite3.Row) -> str:
    line = row["line_int"] if row["line_int"] is not None else row["line_raw"]
    return json.dumps(
        {
            "timestamp_utc": row["timestamp_utc"],
            "timestamp_quality": row["timestamp_quality"],
            "host": row["host"],
            "user": row["user"],
            "source_artifact": row["source_artifact"],
            "event_type": row["event_type"],
            "message": row["message"],
            "evidence_path": row["evidence_path"],
            "line_or_offset": line,
            "raw": row["raw"],
            "tags": json.loads(row["tags_json"]),
            "mitre_ids": json.loads(row["mitre_json"]),
            "confidence": row["confidence"],
            "parser": row["parser"],
            "repeat_count": row["repeat_count"],
        },
        ensure_ascii=False,
    )


def _row_to_csv(row: sqlite3.Row) -> list:
    line = row["line_int"] if row["line_int"] is not None else row["line_raw"]
    return [
        row["timestamp_utc"] or "",
        row["timestamp_quality"],
        row["suspicious_time"],
        row["host"] or "",
        row["user"] or "",
        row["source_artifact"],
        row["event_type"],
        row["message"],
        row["evidence_path"],
        line if line is not None else "",
        ";".join(json.loads(row["tags_json"])),
        ";".join(json.loads(row["mitre_json"])),
        row["confidence"],
        row["parser"],
        row["repeat_count"],
    ]


class Timeline:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA_SQL)

    @classmethod
    def build(
        cls,
        path: str | Path,
        events: Iterator[Event],
        *,
        collection_time_utc: datetime,
        batch: int = BATCH_SIZE,
    ) -> Timeline:
        target = Path(path)
        if target.exists():
            target.unlink()
        timeline = cls(target)
        timeline.add_events(events, collection_time_utc, batch=batch)
        return timeline

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Timeline:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def add_events(
        self, events: Iterator[Event], collection_time_utc: datetime, *, batch: int = BATCH_SIZE
    ) -> dict:
        before = len(self)
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('collection_time_utc', ?)",
            (collection_time_utc.isoformat(),),
        )
        attempted = 0
        pending: list[tuple] = []
        with self.conn:
            for event in events:
                pending.append(_event_to_row(event, collection_time_utc))
                attempted += 1
                if len(pending) >= batch:
                    self.conn.executemany(INSERT_SQL, pending)
                    pending = []
            if pending:
                self.conn.executemany(INSERT_SQL, pending)
        stored = len(self) - before
        return {"attempted": attempted, "stored": stored, "duplicates": attempted - stored}

    def __len__(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def undated_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events WHERE timestamp_utc IS NULL").fetchone()[0]

    def _select(self, where: str = "", params: tuple = (), limit: int | None = None) -> Iterator[Event]:
        sql = f"SELECT * FROM events {where} ORDER BY {ORDER_BY}"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        for row in self.conn.execute(sql, params):
            yield _row_to_event(row)

    def iter_ordered(self) -> Iterator[Event]:
        yield from self._select("WHERE timestamp_utc IS NOT NULL")

    def iter_undated(self) -> Iterator[Event]:
        for row in self.conn.execute(f"SELECT * FROM events WHERE timestamp_utc IS NULL ORDER BY {UNDATED_ORDER_BY}"):
            yield _row_to_event(row)

    def iter_suspicious(self) -> Iterator[Event]:
        yield from self._select("WHERE suspicious_time = 1")

    def query(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        user: str | None = None,
        event_type: str | None = None,
        source_artifact: str | None = None,
        ip: str | None = None,
        limit: int | None = None,
    ) -> Iterator[Event]:
        clauses = []
        params: list = []
        for label, value in (("start", start), ("end", end)):
            if value is not None and value.tzinfo is None:
                raise ValueError(f"query {label} must be timezone-aware")
        if start is not None:
            clauses.append("timestamp_utc >= ?")
            params.append(start.astimezone(UTC).isoformat())
        if end is not None:
            clauses.append("timestamp_utc <= ?")
            params.append(end.astimezone(UTC).isoformat())
        if user is not None:
            clauses.append("user = ?")
            params.append(user)
        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type)
        if source_artifact is not None:
            clauses.append("source_artifact = ?")
            params.append(source_artifact)
        if ip is not None:
            clauses.append("(message LIKE '%' || ? || '%' OR raw LIKE '%' || ? || '%')")
            params.extend([ip, ip])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        yield from self._select(where, tuple(params), limit)

    def around(self, center: datetime, minutes: int = 30) -> Iterator[Event]:
        delta = timedelta(minutes=minutes)
        yield from self.query(start=center - delta, end=center + delta)

    def around_finding(self, finding: Finding, minutes: int = 30) -> Iterator[Event]:
        if finding.first_seen is None and finding.last_seen is None:
            return iter(())
        start = finding.first_seen
        end = finding.last_seen if finding.last_seen is not None else finding.first_seen
        delta = timedelta(minutes=minutes)
        yield from self.query(start=start - delta, end=end + delta)

    def stats(self) -> dict:
        total = len(self)
        undated = self.undated_count()
        per_artifact = {
            row["source_artifact"]: row["n"]
            for row in self.conn.execute("SELECT source_artifact, COUNT(*) AS n FROM events GROUP BY source_artifact")
        }
        per_day = {
            row["day"]: row["n"]
            for row in self.conn.execute(
                "SELECT substr(timestamp_utc, 1, 10) AS day, COUNT(*) AS n "
                "FROM events WHERE timestamp_utc IS NOT NULL GROUP BY day ORDER BY day"
            )
        }
        per_type = {
            row["event_type"]: row["n"]
            for row in self.conn.execute("SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type")
        }
        suspicious = self.conn.execute("SELECT COUNT(*) FROM events WHERE suspicious_time = 1").fetchone()[0]
        return {
            "total": total,
            "dated": total - undated,
            "undated": undated,
            "suspicious_time": suspicious,
            "per_artifact": per_artifact,
            "per_day": per_day,
            "per_event_type": per_type,
        }

    def write_jsonl(self, path: str | Path) -> int:
        count = 0
        with open(path, "w", encoding="utf-8") as handle:
            for row in self.conn.execute(f"SELECT * FROM events WHERE timestamp_utc IS NOT NULL ORDER BY {ORDER_BY}"):
                handle.write(_row_to_json(row) + "\n")
                count += 1
            for row in self.conn.execute(
                f"SELECT * FROM events WHERE timestamp_utc IS NULL ORDER BY {UNDATED_ORDER_BY}"
            ):
                handle.write(_row_to_json(row) + "\n")
                count += 1
        return count

    def write_csv(self, path: str | Path) -> int:
        count = 0
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(CSV_HEADER)
            for row in self.conn.execute(f"SELECT * FROM events WHERE timestamp_utc IS NOT NULL ORDER BY {ORDER_BY}"):
                writer.writerow(_row_to_csv(row))
                count += 1
            for row in self.conn.execute(
                f"SELECT * FROM events WHERE timestamp_utc IS NULL ORDER BY {UNDATED_ORDER_BY}"
            ):
                writer.writerow(_row_to_csv(row))
                count += 1
        return count
