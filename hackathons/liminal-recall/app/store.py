from __future__ import annotations

import json
import os
import uuid
from typing import Any, Protocol

from .embeddings import BedrockTitanEmbedder, Embedder, memory_embedding_text
from .models import MemoryCreate, MemoryRecord


class MemoryStore(Protocol):
    def create_memory(self, memory: MemoryCreate) -> MemoryRecord: ...

    def list_memories(self, session_id: str, limit: int = 20) -> list[MemoryRecord]: ...


class SemanticMemoryStore(MemoryStore, Protocol):
    def find_relevant_negative_outcomes(
        self,
        session_id: str,
        proposed_action: str,
        tags: list[str],
        limit: int = 3,
    ) -> list[MemoryRecord]: ...


class CockroachMemoryStore:
    def __init__(
        self,
        database_url: str,
        embedder: Embedder | None = None,
        similarity_threshold: float = 0.35,
    ) -> None:
        if not database_url:
            raise ValueError("DATABASE_URL is required")
        if not 0.0 <= similarity_threshold <= 2.0:
            raise ValueError("SIMILARITY_THRESHOLD must be between 0 and 2")
        self.database_url = database_url
        self.embedder = embedder or BedrockTitanEmbedder.from_env()
        self.similarity_threshold = similarity_threshold

    @classmethod
    def from_env(cls) -> "CockroachMemoryStore":
        return cls(
            os.environ.get("DATABASE_URL", ""),
            similarity_threshold=float(os.getenv("SIMILARITY_THRESHOLD", "0.35")),
        )

    def _connect(self) -> Any:
        # Import the database driver only when a live CockroachDB connection is used.
        # This keeps the pure decision engine testable inside CML's protected CI.
        import psycopg
        from psycopg.rows import dict_row

        return psycopg.connect(
            self.database_url,
            row_factory=dict_row,
            connect_timeout=8,
            application_name="liminal-recall",
        )

    def create_memory(self, memory: MemoryCreate) -> MemoryRecord:
        from psycopg.types.json import Jsonb

        memory_id = str(uuid.uuid4())
        embedding = self.embedder.embed(memory_embedding_text(memory.content, memory.tags))
        vector = _vector_literal(embedding, self.embedder.dimensions)

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
                    confidence, parent_memory_id, embedding
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::VECTOR)
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
                    vector,
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

    def find_relevant_negative_outcomes(
        self,
        session_id: str,
        proposed_action: str,
        tags: list[str],
        limit: int = 3,
    ) -> list[MemoryRecord]:
        bounded_limit = max(1, min(limit, 10))
        candidate_limit = min(max(bounded_limit * 4, 12), 50)
        embedding = self.embedder.embed(memory_embedding_text(proposed_action, tags))
        vector = _vector_literal(embedding, self.embedder.dimensions)

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, session_id, kind, content, tags, status,
                       confidence, parent_memory_id, created_at,
                       embedding <=> %s::VECTOR AS semantic_distance
                FROM agent_memories
                WHERE session_id = %s
                  AND kind = 'outcome'
                  AND status = 'negative'
                  AND embedding IS NOT NULL
                ORDER BY embedding <=> %s::VECTOR ASC,
                         confidence DESC,
                         created_at DESC
                LIMIT %s
                """,
                (vector, session_id, vector, candidate_limit),
            ).fetchall()

        selected = [
            _to_record(row)
            for row in rows
            if float(row["semantic_distance"]) <= self.similarity_threshold
        ]
        return selected[:bounded_limit]


def _vector_literal(values: list[float], expected_dimensions: int) -> str:
    if len(values) != expected_dimensions:
        raise ValueError("embedding vector dimension mismatch")
    return json.dumps([round(float(value), 8) for value in values], separators=(",", ":"))


def _to_record(row: dict[str, Any]) -> MemoryRecord:
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
