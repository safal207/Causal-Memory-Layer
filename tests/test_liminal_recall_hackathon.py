from __future__ import annotations

import io
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1] / "hackathons" / "liminal-recall"
sys.path.insert(0, str(APP_ROOT))

from app.embeddings import BedrockTitanEmbedder
from app.handler import lambda_handler, set_store_for_tests
from app.models import MemoryCreate, MemoryRecord


class InMemoryStore:
    def __init__(self) -> None:
        self.records: list[MemoryRecord] = []

    def create_memory(self, memory: MemoryCreate) -> MemoryRecord:
        if memory.parent_memory_id is not None and not any(
            record.id == memory.parent_memory_id
            and record.session_id == memory.session_id
            for record in self.records
        ):
            raise ValueError("parent_memory_id does not exist in this session")
        record = MemoryRecord(
            **memory.model_dump(),
            id=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
        )
        self.records.append(record)
        return record

    def list_memories(self, session_id: str, limit: int = 20) -> list[MemoryRecord]:
        matches = [
            record for record in reversed(self.records) if record.session_id == session_id
        ]
        return matches[:limit]


class SemanticInMemoryStore(InMemoryStore):
    def find_relevant_negative_outcomes(
        self,
        session_id: str,
        proposed_action: str,
        tags: list[str],
        limit: int = 3,
    ) -> list[MemoryRecord]:
        del proposed_action, tags
        matches = [
            record
            for record in reversed(self.records)
            if record.session_id == session_id
            and record.kind == "outcome"
            and record.status == "negative"
        ]
        return matches[:limit]


def _call(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    event = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
    }
    if body is not None:
        event["body"] = json.dumps(body)
    response = lambda_handler(event, None)
    return response["statusCode"], json.loads(response["body"])


def test_liminal_recall_uses_persistent_negative_memory_for_later_decision():
    store = InMemoryStore()
    set_store_for_tests(store)
    try:
        status, outcome = _call(
            "POST",
            "/memories",
            {
                "session_id": "payments-agent",
                "kind": "outcome",
                "content": "Refund was sent twice after retry without idempotency key",
                "tags": ["refund", "payment", "retry"],
                "status": "negative",
                "confidence": 0.98,
            },
        )
        assert status == 201

        status, decision = _call(
            "POST",
            "/decisions",
            {
                "session_id": "payments-agent",
                "proposed_action": "Retry the customer refund payment",
                "tags": ["refund", "payment", "retry"],
            },
        )
        assert status == 200
        assert decision["decision"] == "HUMAN_REVIEW"
        assert decision["memory_ids"] == [outcome["id"]]
        assert decision["retrieval"]["mode"] == "deterministic_token_overlap"
        assert decision["execution"] == {
            "status": "NOT_EXECUTED",
            "authority": "advisory_only",
        }

        stored_decision = next(
            record
            for record in store.records
            if record.id == decision["decision_memory_id"]
        )
        assert stored_decision.parent_memory_id == outcome["id"]
    finally:
        set_store_for_tests(None)


def test_liminal_recall_reports_vector_tool_for_semantic_store():
    store = SemanticInMemoryStore()
    set_store_for_tests(store)
    try:
        outcome = store.create_memory(
            MemoryCreate(
                session_id="payments-agent",
                kind="outcome",
                content="Duplicate disbursement after a non-idempotent retry",
                status="negative",
                confidence=0.99,
            )
        )
        status, decision = _call(
            "POST",
            "/decisions",
            {
                "session_id": "payments-agent",
                "proposed_action": "Send the customer reimbursement again",
            },
        )
        assert status == 200
        assert decision["memory_ids"] == [outcome.id]
        assert decision["retrieval"] == {
            "mode": "cockroachdb_vector_cosine",
            "memory_layer": "cockroachdb",
            "tool": "distributed_vector_index",
        }
    finally:
        set_store_for_tests(None)


def test_titan_embedding_contract_is_stable():
    class FakeClient:
        def invoke_model(self, **kwargs):
            request = json.loads(kwargs["body"])
            assert request["dimensions"] == 256
            assert request["normalize"] is True
            return {"body": io.BytesIO(json.dumps({"embedding": [0.1] * 256}).encode())}

    vector = BedrockTitanEmbedder(client=FakeClient()).embed("refund retry")
    assert len(vector) == 256
