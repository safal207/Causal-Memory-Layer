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

