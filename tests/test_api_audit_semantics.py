import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from api.server import app


client = TestClient(app)


def _record(
    record_id,
    action,
    object_,
    permitted_by,
    parent_cause=None,
    pid=100,
):
    return {
        "id": record_id,
        "timestamp": 1_000_000_000,
        "actor": {"pid": pid, "uid": 1000},
        "action": action,
        "object": object_,
        "permitted_by": permitted_by,
        "parent_cause": parent_cause,
    }


def _audit(records):
    log = "\n".join(json.dumps(record) for record in records)
    response = client.post("/audit", json={"log": log, "format": "json"})
    assert response.status_code == 200
    return response.json()


def _codes(result):
    return [finding["code"] for finding in result["findings"]]


def test_api_audit_reports_missing_parent():
    result = _audit(
        [
            _record(
                "child",
                "open",
                "/etc/passwd",
                "fs:read",
                parent_cause="missing-parent",
            )
        ]
    )

    assert "CML-AUDIT-R1-MISSING_PARENT" in _codes(result)
    assert result["summary"]["passed"] is False


def test_api_audit_reports_unmarked_gap_without_failure():
    result = _audit(
        [
            _record(
                "gap",
                "exec",
                "/bin/task",
                "manual-operator-context",
                parent_cause=None,
            )
        ]
    )

    assert "CML-AUDIT-R2-GAP_NOT_MARKED" in _codes(result)
    assert result["summary"]["passed"] is True


def test_api_audit_reports_ambiguous_root_without_gap_warning():
    result = _audit(
        [
            _record(
                "near-root",
                "exec",
                "/sbin/init",
                "root_event",
                parent_cause=None,
            )
        ]
    )

    codes = _codes(result)
    assert "CML-AUDIT-R4-AMBIGUOUS_ROOT" in codes
    assert "CML-AUDIT-R2-GAP_NOT_MARKED" not in codes
    assert result["summary"]["passed"] is True


def test_api_audit_reports_secret_to_network_missing_chain():
    result = _audit(
        [
            _record(
                "secret-read",
                "open",
                {"path": "/secrets/api.key", "classification": "SECRET"},
                "root_event:init",
                parent_cause=None,
                pid=200,
            ),
            _record(
                "network-send",
                "connect",
                {"addr": "203.0.113.10", "port": 443},
                "unobserved_parent",
                parent_cause=None,
                pid=200,
            ),
        ]
    )

    assert "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN" in _codes(result)
    assert result["summary"]["passed"] is False
