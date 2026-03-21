"""
api.store — Pluggable log store backends

Provides InMemoryStore (default) and SQLiteStore (persistent + TTL eviction).

Select backend via CML_STORE_PATH env var:
    - unset / empty  → InMemoryStore
    - path to .db     → SQLiteStore with 24h TTL (override via CML_STORE_TTL)
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Protocol

from cml.record import CausalRecord


# ---------------------------------------------------------------------------
# Protocol (interface)
# ---------------------------------------------------------------------------

class LogStore(Protocol):
    def get(self, log_name: str) -> list[CausalRecord]: ...
    def store(self, log_name: str, records: list[CausalRecord]) -> int: ...
    def log_count(self) -> int: ...
    def record_count(self, log_name: str) -> int: ...


# ---------------------------------------------------------------------------
# In-memory store (community tier default)
# ---------------------------------------------------------------------------

_MAX_LOGS = 1_000
_MAX_RECORDS_PER_LOG = 100_000


class InMemoryStore:
    def __init__(self) -> None:
        self._logs: dict[str, list[CausalRecord]] = {}
        self._ids: dict[str, set[str]] = {}

    def get(self, log_name: str) -> list[CausalRecord]:
        return self._logs.get(log_name, [])

    def store(self, log_name: str, records: list[CausalRecord]) -> int:
        if log_name not in self._logs and len(self._logs) >= _MAX_LOGS:
            raise StoreLimitError("Too many logs (community tier limit).")
        existing = self._logs.setdefault(log_name, [])
        ids = self._ids.setdefault(log_name, {r.id for r in existing})
        added = 0
        for r in records:
            if len(existing) >= _MAX_RECORDS_PER_LOG:
                raise StoreLimitError(
                    f"Log '{log_name}' exceeds {_MAX_RECORDS_PER_LOG} record limit."
                )
            if r.id not in ids:
                existing.append(r)
                ids.add(r.id)
                added += 1
        return added

    def log_count(self) -> int:
        return len(self._logs)

    def record_count(self, log_name: str) -> int:
        return len(self._logs.get(log_name, []))


# ---------------------------------------------------------------------------
# SQLite store (persistent + TTL eviction)
# ---------------------------------------------------------------------------

class SQLiteStore:
    """Persistent log store backed by SQLite with automatic TTL eviction."""

    def __init__(self, path: str, ttl_seconds: int = 86_400) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._ttl = ttl_seconds
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS records (
                log_name  TEXT NOT NULL,
                record_id TEXT NOT NULL,
                data      TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (log_name, record_id)
            );
            CREATE INDEX IF NOT EXISTS idx_records_log
                ON records(log_name);
        """)
        self._conn.commit()

    def get(self, log_name: str) -> list[CausalRecord]:
        self._evict()
        rows = self._conn.execute(
            "SELECT data FROM records WHERE log_name = ? ORDER BY created_at",
            (log_name,),
        ).fetchall()
        return [CausalRecord.from_json(row[0]) for row in rows]

    def store(self, log_name: str, records: list[CausalRecord]) -> int:
        self._evict()
        now = time.time()
        added = 0
        for r in records:
            try:
                self._conn.execute(
                    "INSERT INTO records (log_name, record_id, data, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (log_name, r.id, r.to_jsonl(), now),
                )
                added += 1
            except sqlite3.IntegrityError:
                pass  # duplicate record_id — skip
        self._conn.commit()
        return added

    def log_count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(DISTINCT log_name) FROM records"
        ).fetchone()
        return row[0]

    def record_count(self, log_name: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM records WHERE log_name = ?", (log_name,)
        ).fetchone()
        return row[0]

    def _evict(self) -> None:
        cutoff = time.time() - self._ttl
        self._conn.execute(
            "DELETE FROM records WHERE created_at < ?", (cutoff,)
        )

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class StoreLimitError(Exception):
    pass
