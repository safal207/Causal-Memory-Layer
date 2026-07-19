from __future__ import annotations

import os
import uuid
from typing import Protocol

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .models import MemoryCreate, MemoryRecord


class MemoryStore(Protocol):
    def create_memory(self, memory: MemoryCreate) -> MemoryRecord: ...

    def list_memories(self, session_id: str, limit: int = 20) -> list[MemoryRecord]: ...


class CockroachMemoryStore:
    def __init__(self, database_url: str) -> None:
        if not database_url:
            raise ValueError("DATABASE_URL is required")
        self.database_url = database_url

    @classmethod
    def from_env(cls) -> "CockroachMemoryStore":
        return cls(os.environ.get("DATABASE_URL", ""))

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(
            self.database_url,
            row_factory=dict_row,
            connect_timeout=8,
            application_name="liminal-recall",
        )

    def create_memory(self, memory: MemoryCreate) -> MemoryRecord:
        memory_id = str(uuid.uuid4())
        with self._connect() as conn:
            if memory.parent_memory_id is not None:
                parent = conn.execute(
                    "SELECT id FROM agent_memories WHERE id = %s AND session_id = %s",
                    (memory.parent_memory_id, memory.session_id),
                ).fetchone()
                if parent is None:
                    raise ValueError("parent_memory_id does not exist in this session")

            row = conn.execute(
                """
                INSERT INTO agent_memories (
                    id, session_id, kind, content, tags, status,
                    confidence, parent_memory_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, session_id, kind, content, tags, status,
                          confidence, parent_memory_id, created_at
                """,
                (
                    memory_id,
                    memory.session_id,
                    memory.kind,
                    memory.content,
                    Jsonb(memory.tags),
                    memory.status,
                    memory.confidence,
                    memory.parent_memory_id,
                ),
            ).fetchone()
        if row is None:
            raise RuntimeError("CockroachDB did not return the inserted memory")
        return _to_record(row)

    def list_memories(self, session_id: str, limit: int = 20) -> list[MemoryRecord]:
        bounded_limit = max(1, min(limit, 100))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, session_id, kind, content, tags, status,
                       confidence, parent_memory_id, created_at
                FROM agent_memories
                WHERE session_id = %s
                ORDER BY created_at DESC, id DESC
                LIMIT %s
                """,
                (session_id, bounded_limit),
            ).fetchall()
        return [_to_record(row) for row in rows]


def _to_record(row: dict) -> MemoryRecord:
    return MemoryRecord(
        id=str(row["id"]),
        session_id=str(row["session_id"]),
        kind=str(row["kind"]),
        content=str(row["content"]),
        tags=list(row["tags"] or []),
        status=str(row["status"]),
        confidence=float(row["confidence"]),
        parent_memory_id=(
            str(row["parent_memory_id"]) if row["parent_memory_id"] is not None else None
        ),
        created_at=row["created_at"],
    )
