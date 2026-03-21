"""
CML Audit API Server (FastAPI)

Endpoints:
    POST /audit           — Audit a JSONL log (body: raw JSONL text)
    POST /audit/file      — Audit an uploaded JSONL file
    POST /ingest          — Append records to a named log store
    GET  /chain/{id}      — Reconstruct causal chain for a record id
    GET  /records/{log}   — List records in a named log
    GET  /health          — Health check

Authentication (Pro/Enterprise):
    Bearer token via Authorization header.
    Community tier: no auth required, logs not persisted.

Run:
    uvicorn api.server:app --reload --port 8080
"""

from __future__ import annotations

import json
import os
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
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Bearer-token auth (enabled when CML_API_TOKEN env var is set)
# ---------------------------------------------------------------------------

_API_TOKEN = os.environ.get("CML_API_TOKEN")

if _API_TOKEN:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse as _AuthJSONResponse

    class _BearerAuthMiddleware(BaseHTTPMiddleware):
        _PUBLIC = {"/health", "/docs", "/redoc", "/openapi.json"}

        async def dispatch(self, request: Request, call_next):
            if request.url.path in self._PUBLIC:
                return await call_next(request)
            auth = request.headers.get("authorization", "")
            if not auth.startswith("Bearer ") or auth[7:] != _API_TOKEN:
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
_store_ttl = int(os.environ.get("CML_STORE_TTL", "86400"))

_store = (
    SQLiteStore(_store_path, ttl_seconds=_store_ttl)
    if _store_path
    else InMemoryStore()
)


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
    records = []
    for raw in req.records:
        try:
            records.append(CausalRecord.from_dict(raw))
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid record: {e}")
    _store_records(req.log_name, records)
    return {"log_name": req.log_name, "ingested": len(records)}


@app.get("/records/{log_name}")
def list_records(log_name: str):
    """List all records in a named log."""
    records = _get_log(log_name)
    if not records:
        raise HTTPException(status_code=404, detail=f"Log '{log_name}' not found.")
    return {"log_name": log_name, "count": len(records),
            "records": [r.to_dict() for r in records]}


@app.get("/records/{log_name}/audit")
def audit_stored_log(log_name: str):
    """Run audit on a stored log."""
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
    if isinstance(raw, str):
        s = raw.strip()
        val = int(s, 16) if s.startswith(("0x", "0X")) else int(s)
    else:
        val = int(raw)
    return decode_ctag(val)
