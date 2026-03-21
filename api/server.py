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
# TODO(Pro/Enterprise): add Bearer-token auth middleware here.

# ---------------------------------------------------------------------------
# In-memory log store (Community tier)
# Keyed by log_name → list[CausalRecord]
# TODO(Pro/Enterprise): replace with a persistent store + TTL eviction.
# ---------------------------------------------------------------------------

_log_store: dict[str, list[CausalRecord]] = {}


def _get_log(log_name: str) -> list[CausalRecord]:
    return _log_store.get(log_name, [])


def _store_records(log_name: str, records: list[CausalRecord]):
    existing = _log_store.setdefault(log_name, [])
    existing_ids = {r.id for r in existing}
    for r in records:
        if r.id not in existing_ids:
            existing.append(r)


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
    val = int(str(raw), 16) if isinstance(raw, str) else int(raw)
    return decode_ctag(val)
