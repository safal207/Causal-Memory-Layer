"""
Technical Note: Challenges & Resolutions Resolved During Development

1. Strict CausalRecord Validation:
   - Challenge: Initial test payloads failed because the CML engine requires a specific schema for the actor field.
   - Resolution: Identified that actor must be a dictionary containing at least pid (Process ID) and uid (User ID) as integers.

2. Mandatory vCML Fields:
   - Challenge: CML validation logic requires more than just an ID and an action to consider a record "well-formed."
   - Resolution: Updated the smoke test payload to include all mandatory fields: timestamp, object, and permitted_by. Specifically, permitted_by must start with the configured root_event: prefix to pass as a valid root record.

3. API Response Schema Mismatch:
   - Challenge: Tests initially failed with a KeyError: 'status' when asserting the response.
   - Resolution: By inspecting api/server.py and AuditResult.to_dict() in cml/audit.py, I determined that the /audit endpoint returns a summary object instead of a top-level status key. The assertion was updated to check data["summary"]["passed"].

4. Dependency Management:
   - Challenge: The FastAPI TestClient failed due to a missing httpx dependency.
   - Resolution: Manually installed httpx in the virtual environment to support asynchronous request simulation.
"""

import pytest
from fastapi.testclient import TestClient
from api.server import app

# Simulating a client
client = TestClient(app)

def test_get_health():
    """Verify that the health endpoint returns a valid status and version."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data

def test_post_audit_minimal_payload():
    """Verify that the audit accepts a minimal valid causal log."""
    payload = {
        "log": '{"id":"r1","timestamp":1,"actor":{"pid":1,"uid":1},"action":"exec","object":"/bin/sh","permitted_by":"root_event:init"}\n',
        "format": "json"
    }
    response = client.post("/audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "summary" in data
    assert data["summary"]["passed"] is True

def test_post_ctag_decode_valid():
    """Verify decoding of a valid hexadecimal CTAG."""
    response = client.post("/ctag/decode", json={"ctag": "0x1234"})
    assert response.status_code == 200
    assert "dom_name" in response.json()

def test_post_ctag_decode_invalid():
    """Verify that an invalid CTAG returns a 422 error."""
    response = client.post("/ctag/decode", json={"ctag": "not-a-hex-code"})
    assert response.status_code == 422