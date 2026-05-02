"""
CML Audit API Server (FastAPI)

Endpoints:
    POST /audit                    — Audit a JSONL log
                                     Body: {"log": "<JSONL>", "config": "<YAML>", "format": "json|markdown|text"}
    POST /audit/file               — Audit an uploaded JSONL file (multipart/form-data)
    POST /ingest                   — Append records to a named log store
                                     Body: {"log_name": "...", "records": [...]}
    GET  /records/{log_name}       — List records in a named log
    GET  /records/{log_name}/audit — Run audit on a stored log
    GET  /chain/{log_name}/{id}    — Reconstruct causal chain for a record
    POST /ctag/decode              — Decode a 16-bit CTAG value
                                     Body: {"ctag": <int|hex_string>}
    GET  /health                   — Health check

Authentication:
    Set CML_API_TOKEN env var to enable Bearer-token auth on all endpoints
    except /health, /docs*, /redoc*. Community tier: unset = no auth.
    Token comparison is constant-time (hmac.compare_digest).

Store backend:
    Set CML_STORE_PATH to a .db file path to enable SQLite persistence.
    Unset = in-memory store (ephemeral, community tier).

Hardening env vars:
    CML_CORS_ORIGINS — comma-separated allowed origins. With auth enabled the
                       default is empty (deny). Without auth the default is
                       "*". Use "*" explicitly to opt into permissive CORS.
    CML_DISABLE_DOCS — when truthy, hides /docs and /redoc.
    CML_STORE_TTL    — SQLite TTL in seconds (1..31_536_000, default 86_400).

Run:
    uvicorn api.server:app --reload --port 8080
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import sys
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from cml import (
    CausalRecord, load_jsonl, records_to_index,
    AuditEngine, AuditConfig, AuditResult,
    reconstruct_chain,
    to_markdown, to_json, to_text,
    decode_ctag,
)
from api.store import InMemoryStore, SQLiteStore, StoreLimitError


logger = logging.getLogger("cml.api")


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 0, maximum: int = 2**31 - 1) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        val = int(raw)
    except (TypeError, ValueError):
        logger.warning("Invalid %s=%r — falling back to default %d", name, raw, default)
        return default
    if val < minimum or val > maximum:
        logger.warning(
            "%s=%d out of range [%d, %d] — clamping to default %d",
            name, val, minimum, maximum, default,
        )
        return default
    return val


def _env_csv(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
#
# CML_API_TOKEN        — Bearer token; unset disables auth (community tier)
# CML_CORS_ORIGINS     — comma-separated allowed origins. Required when token
#                        auth is enabled; otherwise defaults to "*".
#                        Use "*" explicitly to opt into permissive CORS.
# CML_DISABLE_DOCS     — when truthy, disables /docs and /redoc (recommended
#                        in production deployments behind authentication).
# CML_STORE_PATH       — SQLite DB path; empty/unset → in-memory ephemeral
# CML_STORE_TTL        — TTL in seconds (default 86400 = 24h, 0 < ttl ≤ 1y)
# ---------------------------------------------------------------------------

_API_TOKEN = os.environ.get("CML_API_TOKEN") or None
_DISABLE_DOCS = _env_bool("CML_DISABLE_DOCS", default=False)


def _resolve_cors_origins() -> list[str]:
    """Pick safe CORS defaults.

    With auth enabled, default-deny (empty list) unless explicitly configured.
    Without auth, "*" is acceptable since there are no credentials to leak.
    Explicit CML_CORS_ORIGINS=* opts in to permissive CORS.
    """
    configured = _env_csv("CML_CORS_ORIGINS")
    if configured:
        return configured
    if _API_TOKEN:
        # Default-deny: do not allow arbitrary cross-origin browsers to reach
        # an authenticated API. Operators must opt in explicitly.
        return []
    return ["*"]


_CORS_ORIGINS = _resolve_cors_origins()


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CML Audit API",
    description=(
        "Causal Memory Layer — REST API for causal log ingestion, "
        "audit, and chain reconstruction."
    ),
    version="0.4.0",
    docs_url=None if _DISABLE_DOCS else "/docs",
    redoc_url=None if _DISABLE_DOCS else "/redoc",
)

# Methods are restricted to those the API actually serves. Allowed headers are
# limited to what the API consumes — anything else gets blocked at the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# ---------------------------------------------------------------------------
# Bearer-token auth (enabled when CML_API_TOKEN env var is set)
# ---------------------------------------------------------------------------

if _API_TOKEN:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse as _AuthJSONResponse

    _TOKEN_BYTES = _API_TOKEN.encode("utf-8")

    class _BearerAuthMiddleware(BaseHTTPMiddleware):
        _PUBLIC_EXACT = {"/health", "/openapi.json"}
        _PUBLIC_PREFIX = ("/docs", "/redoc")

        async def dispatch(self, request: Request, call_next):
            path = request.url.path
            if path in self._PUBLIC_EXACT or path.startswith(self._PUBLIC_PREFIX):
                return await call_next(request)
            auth = request.headers.get("authorization", "")
            presented = auth[7:].encode("utf-8") if auth.startswith("Bearer ") else b""
            # Constant-time compare to prevent token-recovery via timing.
            if not hmac.compare_digest(presented, _TOKEN_BYTES):
                client = request.client.host if request.client else "unknown"
                logger.warning("Auth failure on %s from %s", path, client)
                return _AuthJSONResponse(
                    {"detail": "Invalid or missing Bearer token."},
                    status_code=401,
                )
            return await call_next(request)

    app.add_middleware(_BearerAuthMiddleware)

# ---------------------------------------------------------------------------
# Log store (pluggable backend)
#
# CML_STORE_PATH → SQLiteStore with TTL eviction (persistent)
# unset          → InMemoryStore (community tier, ephemeral)
# CML_STORE_TTL  → TTL in seconds (default: 86400 = 24h)
# ---------------------------------------------------------------------------

_store_path = os.environ.get("CML_STORE_PATH", "")
# TTL: clamp to (0, 1 year]. Non-positive or non-integer values fall back to
# 24h so a malformed env var cannot disable eviction or crash startup.
_store_ttl = _env_int("CML_STORE_TTL", default=86_400, minimum=1, maximum=31_536_000)

_store = (
    SQLiteStore(_store_path, ttl_seconds=_store_ttl)
    if _store_path
    else InMemoryStore()
)


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

# log_name flows into SQLite parameters and HTTP path segments. Parameterized
# queries already prevent SQL injection, but unconstrained names enable
# resource exhaustion (millions of distinct logs) and confusing path routing.
_LOG_NAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")


def _validate_log_name(log_name: str) -> str:
    if not isinstance(log_name, str) or not _LOG_NAME_RE.match(log_name):
        raise HTTPException(
            status_code=422,
            detail=(
                "Invalid log_name: must be 1-128 chars, "
                "alphanumeric plus '.', '_', '-'."
            ),
        )
    return log_name


def _get_log(log_name: str) -> list[CausalRecord]:
    return _store.get(log_name)


def _store_records(log_name: str, records: list[CausalRecord]):
    try:
        _store.store(log_name, records)
    except StoreLimitError as e:
        raise HTTPException(status_code=429, detail=str(e))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_jsonl(text: str) -> list[CausalRecord]:
    records = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                records.append(CausalRecord.from_json(line))
            except Exception as e:
                raise HTTPException(
                    status_code=422,
                    detail=f"Failed to parse record: {e}\nLine: {line[:80]}"
                )
    return records


def _run_audit(records: list[CausalRecord], config_yaml: Optional[str] = None) -> AuditResult:
    cfg = AuditConfig.from_yaml_string(config_yaml) if config_yaml else AuditConfig()
    return AuditEngine(cfg).run(records)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class AuditTextRequest(BaseModel):
    log:    str            # Raw JSONL content
    config: Optional[str] = None   # Optional YAML config text
    format: str = "json"   # json | markdown | text


class IngestRequest(BaseModel):
    log_name: str
    records:  list[dict]   # List of raw record dicts


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.4.0"}


@app.post("/audit")
def audit_text(req: AuditTextRequest):
    """
    Audit a JSONL log provided as a string.

    Returns audit result in json, markdown, or text format.
    """
    records = _parse_jsonl(req.log)
    result  = _run_audit(records, req.config)

    if req.format == "markdown":
        index = records_to_index(records)
        return PlainTextResponse(
            to_markdown(result, index=index),
            media_type="text/markdown"
        )
    elif req.format == "text":
        return PlainTextResponse(to_text(result))
    else:
        return JSONResponse(result.to_dict())


@app.post("/audit/file")
async def audit_file(file: UploadFile = File(...)):
    """
    Audit an uploaded JSONL file.
    """
    content = await file.read()
    text    = content.decode("utf-8")
    records = _parse_jsonl(text)
    result  = _run_audit(records)
    return JSONResponse(result.to_dict())


@app.post("/ingest")
def ingest(req: IngestRequest):
    """
    Append records to a named in-memory log.
    """
    log_name = _validate_log_name(req.log_name)
    records = []
    for raw in req.records:
        try:
            records.append(CausalRecord.from_dict(raw))
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid record: {e}")
    _store_records(log_name, records)
    return {"log_name": log_name, "ingested": len(records)}


@app.get("/records/{log_name}")
def list_records(log_name: str):
    """List all records in a named log."""
    log_name = _validate_log_name(log_name)
    records = _get_log(log_name)
    if not records:
        raise HTTPException(status_code=404, detail=f"Log '{log_name}' not found.")
    return {"log_name": log_name, "count": len(records),
            "records": [r.to_dict() for r in records]}


@app.get("/records/{log_name}/audit")
def audit_stored_log(log_name: str):
    """Run audit on a stored log."""
    log_name = _validate_log_name(log_name)
    records = _get_log(log_name)
    if not records:
        raise HTTPException(status_code=404, detail=f"Log '{log_name}' not found.")
    result = _run_audit(records)
    return JSONResponse(result.to_dict())


@app.get("/chain/{log_name}/{record_id}")
def get_chain(log_name: str, record_id: str):
    """
    Reconstruct the causal chain for a record in a stored log.
    """
    log_name = _validate_log_name(log_name)
    records = _get_log(log_name)
    if not records:
        raise HTTPException(status_code=404, detail=f"Log '{log_name}' not found.")
    index = records_to_index(records)
    if record_id not in index:
        raise HTTPException(status_code=404, detail=f"Record '{record_id}' not found.")
    chain = reconstruct_chain(record_id, index)
    return {
        "record_id": record_id,
        "chain_length": len(chain),
        "chain": [r.to_dict() for r in chain],
    }


@app.post("/ctag/decode")
def api_decode_ctag(body: dict = Body(...)):
    """Decode a 16-bit CTAG value."""
    raw = body.get("ctag")
    if raw is None:
        raise HTTPException(status_code=422, detail="Field 'ctag' required.")
    try:
        if isinstance(raw, bool):
            # bool is a subclass of int; reject explicitly to avoid surprises.
            raise ValueError("ctag must be an integer or hex/decimal string")
        if isinstance(raw, str):
            s = raw.strip()
            if not s:
                raise ValueError("ctag string is empty")
            val = int(s, 16) if s.lower().startswith("0x") else int(s)
        elif isinstance(raw, int):
            val = raw
        else:
            raise ValueError(f"unsupported ctag type: {type(raw).__name__}")
    except (TypeError, ValueError) as e:
        raise HTTPException(status_code=422, detail=f"Invalid ctag: {e}")
    if not (0 <= val <= 0xFFFF):
        raise HTTPException(
            status_code=422,
            detail="ctag out of range: must be a 16-bit value in [0, 65535].",
        )
    return decode_ctag(val)
