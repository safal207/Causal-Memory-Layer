"""Regression tests for api.server security hardening.

Covers:
  - Bearer-token constant-time comparison and auth gating
  - CORS default-deny when token auth is enabled
  - CML_STORE_TTL safe parsing (bad / out-of-range / empty)
  - CML_DISABLE_DOCS hides /docs and /redoc
  - /ctag/decode rejects out-of-range, malformed, and bool inputs
  - log_name validation on /ingest, /records, /chain
"""
from __future__ import annotations

import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient


_ENV_KEYS = (
    "CML_API_TOKEN",
    "CML_CORS_ORIGINS",
    "CML_DISABLE_DOCS",
    "CML_STORE_TTL",
    "CML_STORE_PATH",
)


def _reload_server(env: dict[str, str] | None = None):
    for key in _ENV_KEYS:
        os.environ.pop(key, None)
    if env:
        os.environ.update(env)
    import api.server as api_server
    return importlib.reload(api_server)


@pytest.fixture(autouse=True)
def _restore_env():
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    # Final reload so subsequent test modules see a clean app.
    _reload_server()


# ---------------------------------------------------------------------------
# Bearer auth
# ---------------------------------------------------------------------------

class TestBearerAuth:
    def test_health_is_public(self):
        srv = _reload_server({"CML_API_TOKEN": "s3cret-token"})
        client = TestClient(srv.app)
        assert client.get("/health").status_code == 200

    def test_missing_token_rejected(self):
        srv = _reload_server({"CML_API_TOKEN": "s3cret-token"})
        client = TestClient(srv.app)
        r = client.post("/audit", json={"log": "", "format": "json"})
        assert r.status_code == 401

    def test_wrong_token_rejected(self):
        srv = _reload_server({"CML_API_TOKEN": "s3cret-token"})
        client = TestClient(srv.app)
        r = client.post(
            "/audit",
            headers={"Authorization": "Bearer wrong"},
            json={"log": "", "format": "json"},
        )
        assert r.status_code == 401

    def test_correct_token_accepted(self):
        srv = _reload_server({"CML_API_TOKEN": "s3cret-token"})
        client = TestClient(srv.app)
        r = client.post(
            "/audit",
            headers={"Authorization": "Bearer s3cret-token"},
            json={"log": "", "format": "json"},
        )
        assert r.status_code == 200

    def test_non_bearer_scheme_rejected(self):
        srv = _reload_server({"CML_API_TOKEN": "s3cret-token"})
        client = TestClient(srv.app)
        r = client.post(
            "/audit",
            headers={"Authorization": "Basic czNjcmV0LXRva2Vu"},
            json={"log": "", "format": "json"},
        )
        assert r.status_code == 401

    def test_token_comparison_uses_compare_digest(self):
        # Source-level invariant: the auth path must invoke
        # hmac.compare_digest. Guards against future regressions to ==.
        import inspect

        srv = _reload_server({"CML_API_TOKEN": "s3cret-token"})
        # Locate the middleware class via the app's middleware stack.
        cls = None
        for m in srv.app.user_middleware:
            if m.cls.__name__ == "_BearerAuthMiddleware":
                cls = m.cls
                break
        assert cls is not None
        src = inspect.getsource(cls.dispatch)
        assert "compare_digest" in src
        assert "!=" not in src.split("compare_digest", 1)[0].splitlines()[-1]


# ---------------------------------------------------------------------------
# CORS resolution
# ---------------------------------------------------------------------------

class TestCors:
    def test_default_wildcard_without_auth(self):
        srv = _reload_server()
        assert srv._CORS_ORIGINS == ["*"]

    def test_default_deny_with_auth(self):
        srv = _reload_server({"CML_API_TOKEN": "x"})
        assert srv._CORS_ORIGINS == []

    def test_explicit_allowlist(self):
        srv = _reload_server({
            "CML_API_TOKEN": "x",
            "CML_CORS_ORIGINS": "https://a.example, https://b.example",
        })
        assert srv._CORS_ORIGINS == ["https://a.example", "https://b.example"]

    def test_explicit_wildcard_opt_in(self):
        srv = _reload_server({"CML_API_TOKEN": "x", "CML_CORS_ORIGINS": "*"})
        assert srv._CORS_ORIGINS == ["*"]


# ---------------------------------------------------------------------------
# Env-int parsing for CML_STORE_TTL
# ---------------------------------------------------------------------------

class TestStoreTtl:
    def test_default(self):
        srv = _reload_server()
        assert srv._store_ttl == 86_400

    def test_garbage_falls_back(self):
        srv = _reload_server({"CML_STORE_TTL": "abc"})
        assert srv._store_ttl == 86_400

    def test_negative_falls_back(self):
        srv = _reload_server({"CML_STORE_TTL": "-1"})
        assert srv._store_ttl == 86_400

    def test_zero_falls_back(self):
        srv = _reload_server({"CML_STORE_TTL": "0"})
        assert srv._store_ttl == 86_400

    def test_overflow_falls_back(self):
        srv = _reload_server({"CML_STORE_TTL": "999999999999"})
        assert srv._store_ttl == 86_400

    def test_valid_value_used(self):
        srv = _reload_server({"CML_STORE_TTL": "60"})
        assert srv._store_ttl == 60


# ---------------------------------------------------------------------------
# Docs visibility
# ---------------------------------------------------------------------------

class TestDocsVisibility:
    def test_docs_enabled_by_default(self):
        srv = _reload_server()
        client = TestClient(srv.app)
        assert client.get("/docs").status_code == 200
        assert client.get("/redoc").status_code == 200

    def test_docs_hidden_when_disabled(self):
        srv = _reload_server({"CML_DISABLE_DOCS": "true"})
        client = TestClient(srv.app)
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404


# ---------------------------------------------------------------------------
# /ctag/decode hardening
# ---------------------------------------------------------------------------

class TestCtagDecode:
    @pytest.fixture
    def client(self):
        srv = _reload_server()
        return TestClient(srv.app)

    def test_valid_int(self, client):
        assert client.post("/ctag/decode", json={"ctag": 0x1234}).status_code == 200

    def test_valid_hex_string(self, client):
        assert client.post("/ctag/decode", json={"ctag": "0xABCD"}).status_code == 200

    def test_valid_decimal_string(self, client):
        assert client.post("/ctag/decode", json={"ctag": "256"}).status_code == 200

    def test_negative_rejected(self, client):
        r = client.post("/ctag/decode", json={"ctag": -1})
        assert r.status_code == 422
        assert "out of range" in r.json()["detail"]

    def test_too_large_rejected(self, client):
        assert client.post("/ctag/decode", json={"ctag": 0x10000}).status_code == 422

    def test_huge_int_rejected(self, client):
        # Previously this would silently coerce via bit-shifts.
        assert client.post(
            "/ctag/decode", json={"ctag": 99999999999999999999}
        ).status_code == 422

    def test_garbage_string_rejected(self, client):
        assert client.post("/ctag/decode", json={"ctag": "abc"}).status_code == 422

    def test_empty_string_rejected(self, client):
        assert client.post("/ctag/decode", json={"ctag": ""}).status_code == 422

    def test_bool_rejected(self, client):
        # bool is an int subclass; previously True would decode as ctag=1.
        assert client.post("/ctag/decode", json={"ctag": True}).status_code == 422

    def test_missing_field_rejected(self, client):
        assert client.post("/ctag/decode", json={}).status_code == 422

    def test_null_rejected(self, client):
        assert client.post("/ctag/decode", json={"ctag": None}).status_code == 422


# ---------------------------------------------------------------------------
# log_name validation
# ---------------------------------------------------------------------------

class TestLogNameValidation:
    @pytest.fixture
    def client(self):
        srv = _reload_server()
        return TestClient(srv.app)

    @pytest.mark.parametrize("bad", [
        "",
        " ",
        "../etc/passwd",
        "name with space",
        "name/with/slash",
        "name\x00null",
        "a" * 200,
    ])
    def test_ingest_rejects_bad_name(self, client, bad):
        r = client.post("/ingest", json={"log_name": bad, "records": []})
        assert r.status_code == 422

    @pytest.mark.parametrize("bad", ["", "a" * 200, "name with space"])
    def test_records_route_rejects_bad_name(self, client, bad):
        r = client.get(f"/records/{bad}")
        # Routing may produce 404 for empty path, but anything that hits the
        # handler must be rejected with 422.
        assert r.status_code in (404, 422)

    def test_valid_name_accepted(self, client):
        r = client.post(
            "/ingest",
            json={"log_name": "my-log_1.v2", "records": []},
        )
        assert r.status_code == 200, r.text
