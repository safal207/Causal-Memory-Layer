"""Reject malformed identities before hashing, graph traversal, or coercion."""

import json
import sqlite3
import time

import pytest

from cli.audit import audit as cli_audit
from cml.audit import AuditEngine
from cml.record import Actor, CausalRecord, load_jsonl, records_to_index


INVALID_IDENTITIES = [1, 1.5, True, False, ["x"], {"id": "x"}]
INVALID_FIELDS = [
    (field, value)
    for field in ("id", "parent_cause")
    for value in INVALID_IDENTITIES
] + [("id", None)]


def _raw(record_id="root", parent=None):
    return {
        "id": record_id, "timestamp": 1, "actor": {"pid": 1, "uid": 1},
        "action": "exec", "object": "/demo", "permitted_by": "root_event:request",
        "parent_cause": parent,
    }


@pytest.mark.parametrize("field,value", INVALID_FIELDS)
@pytest.mark.parametrize("entrypoint", ["constructor", "from_dict", "from_json", "load_jsonl", "cli_adapter", "mcp"])
def test_invalid_identity_types_are_input_errors(field, value, entrypoint, tmp_path):
    raw = dict(_raw(), **{field: value})
    with pytest.raises(ValueError, match=rf"{field} must be a string"):
        if entrypoint == "constructor":
            CausalRecord(**dict(raw, actor=Actor(pid=1, uid=1)))
        elif entrypoint == "from_dict":
            CausalRecord.from_dict(raw)
        elif entrypoint == "from_json":
            CausalRecord.from_json(json.dumps(raw))
        elif entrypoint == "load_jsonl":
            path = tmp_path / "invalid.jsonl"
            path.write_text(json.dumps(raw) + "\n", encoding="utf-8")
            load_jsonl(str(path))
        elif entrypoint == "cli_adapter":
            cli_audit([raw])
        else:
            from cml.integrations.mcp.core import audit_trace

            audit_trace({"records": [raw]})


@pytest.mark.parametrize("parent", INVALID_IDENTITIES)
def test_new_record_rejects_invalid_parent_type(parent):
    with pytest.raises(ValueError, match="parent_cause must be a string"):
        CausalRecord.new(Actor(pid=1, uid=1), "exec", "/demo", "permission", parent)


@pytest.mark.parametrize("field,value", INVALID_FIELDS)
def test_index_and_audit_revalidate_mutated_record_identities(field, value):
    record = CausalRecord.from_dict(_raw())
    setattr(record, field, value)
    for operation in (records_to_index, AuditEngine().run):
        with pytest.raises(ValueError, match=rf"{field} must be a string"):
            operation([record])


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient
    from api import server
    from api.store import InMemoryStore

    monkeypatch.setattr(server.limiter, "enabled", False)
    monkeypatch.setattr(server, "_store", InMemoryStore())
    with TestClient(server.app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.mark.parametrize("field,value", INVALID_FIELDS)
@pytest.mark.parametrize("endpoint", ["/audit", "/audit/file", "/ingest"])
def test_api_rejects_malformed_identities(client, field, value, endpoint):
    raw = dict(_raw(), **{field: value})
    log = json.dumps(raw)
    if endpoint == "/audit/file":
        response = client.post(endpoint, files={"file": ("trace.jsonl", log, "application/jsonl")})
    elif endpoint == "/ingest":
        response = client.post(endpoint, json={"log_name": "invalid", "records": [raw]})
        assert client.get("/records/invalid").status_code == 404
    else:
        response = client.post(endpoint, json={"log": log})
    assert response.status_code == 422, response.text
    assert f"{field} must be a string" in response.json()["detail"]


@pytest.mark.parametrize("format_", ["json", "markdown", "text"])
@pytest.mark.parametrize("reverse", [False, True])
def test_api_mixed_type_cycle_is_422_in_every_format(client, format_, reverse):
    records = [_raw(1, "a"), _raw("a", 1)]
    if reverse:
        records.reverse()
    response = client.post("/audit", json={
        "log": "\n".join(json.dumps(raw) for raw in records), "format": format_,
    })
    assert response.status_code == 422, response.text
    assert "must be a string" in response.json()["detail"]


def test_numeric_id_is_rejected_rather_than_coerced_to_existing_string(client):
    response = client.post("/audit", json={
        "log": "\n".join(json.dumps(_raw(rid)) for rid in ("1", 1)),
    })
    assert response.status_code == 422
    assert "id must be a string" in response.json()["detail"]
    assert "Duplicate" not in response.json()["detail"]


@pytest.mark.parametrize("endpoint", ["/records/mutated/audit", "/chain/mutated/root"])
def test_api_rejects_mutated_stored_identity(client, monkeypatch, endpoint):
    from api import server
    from api.store import InMemoryStore

    store = InMemoryStore()
    record = CausalRecord.from_dict(_raw())
    store.store("mutated", [record])
    record.parent_cause = ["bad-parent"]
    monkeypatch.setattr(server, "_store", store)
    response = client.get(endpoint)
    assert response.status_code == 422, response.text
    assert "parent_cause must be a string" in response.json()["detail"]


@pytest.mark.parametrize("endpoint", ["/records/legacy", "/records/legacy/audit", "/chain/legacy/root"])
def test_legacy_sqlite_invalid_identity_is_an_input_error(client, monkeypatch, tmp_path, endpoint):
    from api import server
    from api.store import SQLiteStore

    path = tmp_path / "legacy.db"
    store = SQLiteStore(str(path))
    try:
        # Simulate a record persisted before identity-type validation existed.
        with sqlite3.connect(path) as db:
            db.execute(
                "INSERT INTO records (log_name, record_id, data, created_at) VALUES (?, ?, ?, ?)",
                ("legacy", "root", json.dumps(_raw("root", ["bad-parent"])), time.time()),
            )
        monkeypatch.setattr(server, "_store", store)
        response = client.get(endpoint)
        assert response.status_code == 422, response.text
        assert "parent_cause must be a string" in response.json()["detail"]
    finally:
        store.close()


@pytest.mark.parametrize("root_id", ["1", "0001", "6b5a67d1-5d8d-4072-9813-182dc54519a5"])
def test_valid_string_identities_round_trip_unchanged(client, root_id):
    raw = [_raw(root_id), _raw("child", root_id)]
    records = [CausalRecord.from_json(json.dumps(item)) for item in raw]
    assert [record.to_dict() for record in records] == raw
    assert AuditEngine().run(records).passed()
    assert cli_audit(raw)["summary"]["passed"]
    assert client.post("/ingest", json={"log_name": "valid", "records": raw}).status_code == 200
    result = client.get("/records/valid/audit")
    assert result.status_code == 200
    assert result.json()["summary"]["passed"]
    chain = client.get("/chain/valid/child")
    assert chain.status_code == 200
    assert [record["id"] for record in chain.json()["chain"]] == [root_id, "child"]


def test_parent_cause_may_be_omitted_or_null():
    raw = _raw()
    assert CausalRecord.from_dict(raw).parent_cause is None
    del raw["parent_cause"]
    assert CausalRecord.from_dict(raw).parent_cause is None


def test_string_identity_contents_are_not_normalized_or_newly_restricted():
    records = [CausalRecord.from_dict(_raw(rid)) for rid in ("1", "01", "", " ")]
    assert list(records_to_index(records)) == ["1", "01", "", " "]
    assert CausalRecord.from_dict(_raw("child", "")).parent_cause == ""


def test_valid_string_cycle_remains_an_audit_failure(client):
    response = client.post("/audit", json={
        "log": "\n".join(json.dumps(raw) for raw in [_raw("1", "a"), _raw("a", "1")]),
    })
    assert response.status_code == 200
    assert not response.json()["summary"]["passed"]
    assert {finding["code"] for finding in response.json()["findings"]} == {"CML-AUDIT-R1-CYCLE"}
