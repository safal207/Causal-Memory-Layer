"""Regression tests for api.server rate limiting (slowapi).

Covers:
  - Per-IP and per-token bucketing (independent budgets per key).
  - 429 + Retry-After when a limit is exceeded.
  - /health is exempt from limits.
  - Per-route overrides via env vars.
  - CML_RATE_LIMIT_ENABLED=false disables enforcement entirely.
  - X-Forwarded-For only trusted under CML_TRUST_PROXY=1.
"""
from __future__ import annotations

import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("slowapi")
from fastapi.testclient import TestClient


_ENV_KEYS = (
    "CML_API_TOKEN",
    "CML_CORS_ORIGINS",
    "CML_DISABLE_DOCS",
    "CML_STORE_TTL",
    "CML_STORE_PATH",
    "CML_RATE_LIMIT_ENABLED",
    "CML_RATE_LIMIT_DEFAULT",
    "CML_RATE_LIMIT_INGEST",
    "CML_RATE_LIMIT_AUDIT",
    "CML_RATE_LIMIT_RECORDS",
    "CML_RATE_LIMIT_CHAIN",
    "CML_RATE_LIMIT_CTAG",
    "CML_RATE_LIMIT_BACKEND",
    "CML_TRUST_PROXY",
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
    _reload_server()


# ---------------------------------------------------------------------------
# Basic enforcement
# ---------------------------------------------------------------------------

class TestRateLimitEnforcement:
    def test_under_limit_passes(self):
        srv = _reload_server({"CML_RATE_LIMIT_CTAG": "5/minute"})
        client = TestClient(srv.app)
        for _ in range(5):
            r = client.post("/ctag/decode", json={"ctag": 0x10})
            assert r.status_code == 200

    def test_over_limit_returns_429(self):
        srv = _reload_server({"CML_RATE_LIMIT_CTAG": "3/minute"})
        client = TestClient(srv.app)
        for _ in range(3):
            assert client.post("/ctag/decode", json={"ctag": 0}).status_code == 200
        r = client.post("/ctag/decode", json={"ctag": 0})
        assert r.status_code == 429

    def test_429_has_retry_after_header(self):
        srv = _reload_server({"CML_RATE_LIMIT_CTAG": "1/minute"})
        client = TestClient(srv.app)
        client.post("/ctag/decode", json={"ctag": 0})
        r = client.post("/ctag/decode", json={"ctag": 0})
        assert r.status_code == 429
        assert "retry-after" in {k.lower() for k in r.headers.keys()}

    def test_health_is_exempt(self):
        # Even with a 1/minute default, /health must always pass.
        srv = _reload_server({"CML_RATE_LIMIT_DEFAULT": "1/minute"})
        client = TestClient(srv.app)
        for _ in range(20):
            assert client.get("/health").status_code == 200


# ---------------------------------------------------------------------------
# Per-route overrides
# ---------------------------------------------------------------------------

class TestPerRouteLimits:
    def test_routes_have_independent_buckets(self):
        srv = _reload_server({
            "CML_RATE_LIMIT_CTAG": "2/minute",
            "CML_RATE_LIMIT_INGEST": "5/minute",
        })
        client = TestClient(srv.app)
        # Burn the ctag budget.
        for _ in range(2):
            assert client.post("/ctag/decode", json={"ctag": 0}).status_code == 200
        assert client.post("/ctag/decode", json={"ctag": 0}).status_code == 429
        # /ingest still has budget — different route, independent bucket.
        r = client.post("/ingest", json={"log_name": "rate-test", "records": []})
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# Master switch
# ---------------------------------------------------------------------------

class TestDisableSwitch:
    def test_disabled_lets_traffic_through(self):
        srv = _reload_server({
            "CML_RATE_LIMIT_ENABLED": "false",
            "CML_RATE_LIMIT_CTAG": "1/minute",
        })
        client = TestClient(srv.app)
        # 10 requests with a 1/minute limit — all must pass when disabled.
        for _ in range(10):
            r = client.post("/ctag/decode", json={"ctag": 0})
            assert r.status_code == 200
        assert srv.limiter.enabled is False


# ---------------------------------------------------------------------------
# Key function: token vs IP
# ---------------------------------------------------------------------------

class TestKeyFunction:
    def test_token_keying_uses_hashed_prefix(self):
        srv = _reload_server()

        class _StubReq:
            def __init__(self, headers, client_host="1.2.3.4"):
                self.headers = headers
                class _C: pass
                c = _C()
                c.host = client_host
                self.client = c

        key_a = srv._rate_limit_key(_StubReq({"authorization": "Bearer A" * 40}))
        key_b = srv._rate_limit_key(_StubReq({"authorization": "Bearer B" * 40}))
        assert key_a.startswith("tok:")
        assert key_b.startswith("tok:")
        assert key_a != key_b
        # Hash prefix is short and deterministic; raw token must not appear.
        assert "A" * 40 not in key_a
        assert "B" * 40 not in key_b

    def test_ip_keying_when_no_token(self):
        srv = _reload_server()

        class _StubReq:
            def __init__(self, headers, client_host="1.2.3.4"):
                self.headers = headers
                class _C: pass
                c = _C()
                c.host = client_host
                self.client = c

        key = srv._rate_limit_key(_StubReq({}, client_host="9.9.9.9"))
        assert key == "ip:9.9.9.9"

    def test_xff_ignored_without_trust_proxy(self):
        srv = _reload_server()

        class _StubReq:
            def __init__(self, headers, client_host="1.2.3.4"):
                self.headers = headers
                class _C: pass
                c = _C()
                c.host = client_host
                self.client = c

        # Spoofed X-Forwarded-For must be ignored by default — otherwise any
        # client could rotate the header to bypass per-IP limits.
        key = srv._rate_limit_key(
            _StubReq({"x-forwarded-for": "8.8.8.8"}, client_host="1.2.3.4")
        )
        assert key == "ip:1.2.3.4"

    def test_xff_honoured_with_trust_proxy(self):
        srv = _reload_server({"CML_TRUST_PROXY": "true"})

        class _StubReq:
            def __init__(self, headers, client_host="1.2.3.4"):
                self.headers = headers
                class _C: pass
                c = _C()
                c.host = client_host
                self.client = c

        key = srv._rate_limit_key(
            _StubReq({"x-forwarded-for": "8.8.8.8, 10.0.0.1"}, client_host="1.2.3.4")
        )
        assert key == "ip:8.8.8.8"

    def test_token_independent_buckets_via_http(self):
        # Two different bearer tokens should get independent buckets even
        # when they share an IP. Use auth-disabled mode (no token required)
        # but supply Authorization headers anyway — the key function will
        # bucket by token regardless of whether the auth middleware checks.
        srv = _reload_server({"CML_RATE_LIMIT_CTAG": "1/minute"})
        client = TestClient(srv.app)

        # Token A — burns its budget.
        h_a = {"Authorization": "Bearer token-aaaaaaaaaa"}
        assert client.post("/ctag/decode", json={"ctag": 0}, headers=h_a).status_code == 200
        assert client.post("/ctag/decode", json={"ctag": 0}, headers=h_a).status_code == 429

        # Token B — fresh bucket.
        h_b = {"Authorization": "Bearer token-bbbbbbbbbb"}
        assert client.post("/ctag/decode", json={"ctag": 0}, headers=h_b).status_code == 200
