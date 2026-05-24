import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from api.server import app


client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_audit_minimal():
    record = {
        "id": "test-001",
        "timestamp": 1_000_000_000,
        "actor": {"pid": 1, "uid": 0},
        "action": "read",
        "object": "file.txt",
        "permitted_by": "policy-1",
        "parent_cause": None,
    }
    log_line = json.dumps(record)
    response = client.post("/audit", json={"log": log_line, "format": "json"})
    assert response.status_code == 200


def test_ctag_decode_valid():
    response = client.post("/ctag/decode", json={"ctag": 0x1234})
    assert response.status_code == 200


def test_ctag_decode_invalid():
    response = client.post("/ctag/decode", json={"ctag": 0xFFFFF})
    assert response.status_code == 422
