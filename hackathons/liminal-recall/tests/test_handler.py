from __future__ import annotations

import io
import json
import os
import uuid
from datetime import datetime, timezone

import pytest

from app.embeddings import BedrockTitanEmbedder
from app.handler import lambda_handler, set_store_for_tests
from app.models import MemoryCreate, MemoryRecord


TEST_DEMO_KEY = "test-demo-key-1234"


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
        records = [
            record for record in reversed(self.records) if record.session_id == session_id
        ]
        return records[:limit]


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


def call(
    method: str,
    path: str,
    body: dict | None = None,
    query: dict | None = None,
    headers: dict | None = None,
):
    request_headers = (
        {"x-demo-key": TEST_DEMO_KEY}
        if headers is None
        else headers
    )
    event = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "queryStringParameters": query,
        "headers": request_headers,
    }
    if body is not None:
        event["body"] = json.dumps(body)
    response = lambda_handler(event, None)
    return response["statusCode"], json.loads(response["body"])


def setup_function():
    os.environ["DEMO_API_KEY"] = TEST_DEMO_KEY
    set_store_for_tests(InMemoryStore())


def teardown_function():
    os.environ.pop("DEMO_API_KEY", None)
    os.environ.pop("BUILD_SHA", None)
    set_store_for_tests(None)


def test_health_does_not_require_database(monkeypatch: pytest.MonkeyPatch):
    build_sha = "a" * 40
    monkeypatch.setenv("BUILD_SHA", build_sha)

    status, body = call("GET", "/healthz", headers={})

    assert status == 200
    assert body["status"] == "ok"
    assert body["service"] == "liminal-recall"
    assert body["build_sha"] == build_sha
    assert body["runtime_instance_id"]


def test_memory_can_be_stored_and_recalled():
    status, created = call(
        "POST",
        "/memories",
        {
            "session_id": "agent-1",
            "kind": "observation",
            "content": "Customer requested a refund",
            "tags": ["Refund", "customer"],
        },
    )
    assert status == 201
    assert created["tags"] == ["refund", "customer"]

    status, recalled = call(
        "GET",
        "/memories",
        query={"session_id": "agent-1", "limit": "10"},
    )
    assert status == 200
    assert [item["id"] for item in recalled["memories"]] == [created["id"]]


def test_negative_outcome_changes_later_decision():
    status, outcome = call(
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

    status, decision = call(
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
    assert decision["execution"]["status"] == "NOT_EXECUTED"


def test_semantic_store_reports_distributed_vector_retrieval():
    store = SemanticInMemoryStore()
    set_store_for_tests(store)
    outcome = store.create_memory(
        MemoryCreate(
            session_id="payments-agent",
            kind="outcome",
            content="Duplicate disbursement after a non-idempotent retry",
            status="negative",
            confidence=0.99,
        )
    )

    status, decision = call(
        "POST",
        "/decisions",
        {
            "session_id": "payments-agent",
            "proposed_action": "Send the refund again",
        },
    )
    assert status == 200
    assert decision["memory_ids"] == [outcome.id]
    assert decision["retrieval"] == {
        "mode": "cockroachdb_vector_cosine",
        "memory_layer": "cockroachdb",
        "tool": "distributed_vector_index",
    }


def test_no_matching_negative_memory_allows_with_monitoring():
    status, decision = call(
        "POST",
        "/decisions",
        {
            "session_id": "report-agent",
            "proposed_action": "Generate a read-only weekly report",
            "tags": ["report", "read-only"],
        },
    )
    assert status == 200
    assert decision["decision"] == "ALLOW_WITH_MONITORING"
    assert decision["memory_ids"] == []


def test_non_health_routes_fail_closed_when_demo_key_is_missing(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.delenv("DEMO_API_KEY", raising=False)

    status, body = call(
        "GET",
        "/memories",
        query={"session_id": "agent-1"},
        headers={},
    )

    assert status == 401
    assert body["error"] == "unauthorized"


def test_demo_key_protects_non_health_routes(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DEMO_API_KEY", "secret-demo-key")
    status, body = call(
        "GET",
        "/memories",
        query={"session_id": "agent-1"},
        headers={},
    )
    assert status == 401
    assert body["error"] == "unauthorized"

    status, body = call(
        "GET",
        "/memories",
        query={"session_id": "agent-1"},
        headers={"X-Demo-Key": "secret-demo-key"},
    )
    assert status == 200


def test_bedrock_embedder_validates_request_and_response():
    class FakeClient:
        def __init__(self) -> None:
            self.kwargs: dict | None = None

        def invoke_model(self, **kwargs):
            self.kwargs = kwargs
            return {"body": io.BytesIO(json.dumps({"embedding": [0.25] * 256}).encode())}

    client = FakeClient()
    embedder = BedrockTitanEmbedder(dimensions=256, client=client)
    vector = embedder.embed("  retry   refund  ")

    assert len(vector) == 256
    assert client.kwargs is not None
    request = json.loads(client.kwargs["body"])
    assert request == {
        "inputText": "retry refund",
        "dimensions": 256,
        "normalize": True,
        "embeddingTypes": ["float"],
    }


def test_bedrock_embedder_rejects_dimensions_not_backed_by_schema():
    with pytest.raises(ValueError, match="VECTOR\(256\)"):
        BedrockTitanEmbedder(dimensions=512, client=object())
