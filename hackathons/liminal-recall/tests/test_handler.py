from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

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
        records = [
            record for record in reversed(self.records) if record.session_id == session_id
        ]
        return records[:limit]


def call(method: str, path: str, body: dict | None = None, query: dict | None = None):
    event = {
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
        "queryStringParameters": query,
    }
    if body is not None:
        event["body"] = json.dumps(body)
    response = lambda_handler(event, None)
    return response["statusCode"], json.loads(response["body"])


def setup_function():
    set_store_for_tests(InMemoryStore())


def teardown_function():
    set_store_for_tests(None)


def test_health_does_not_require_database():
    status, body = call("GET", "/healthz")
    assert status == 200
    assert body["status"] == "ok"
    assert body["service"] == "liminal-recall"


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
    assert decision["execution"]["status"] == "NOT_EXECUTED"


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
