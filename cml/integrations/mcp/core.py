from __future__ import annotations

from typing import Any

from cml import AuditEngine
from cml.experimental.cause_band import evaluate_fixture
from cml.record import CausalRecord
from scripts.run_experimental_cause_band_eval import extract_fixture_payload


def health() -> dict[str, Any]:
    return {
        "service": "cml-agent-audit-mcp",
        "status": "ok",
        "tools": [
            "health",
            "audit_trace",
            "evaluate_cause_band",
        ],
        "scope": "experimental MCP integration skeleton",
    }


def _records_from_payload(payload: Any) -> list[CausalRecord]:
    if isinstance(payload, dict):
        if isinstance(payload.get("records"), list):
            raw_records = payload["records"]
        elif isinstance(payload.get("agent_trace"), list):
            raw_records = payload["agent_trace"]
        else:
            raise ValueError("Trace payload must contain a 'records' or 'agent_trace' list")
    elif isinstance(payload, list):
        raw_records = payload
    else:
        raise ValueError("Trace payload must be a list or object")

    records: list[CausalRecord] = []
    for index, raw in enumerate(raw_records):
        if not isinstance(raw, dict):
            raise ValueError(f"Trace record at index {index} must be an object")
        records.append(CausalRecord.from_dict(raw))
    return records


def audit_trace(payload: Any) -> dict[str, Any]:
    """Run the core CML audit engine over JSON-compatible records."""
    records = _records_from_payload(payload)
    return AuditEngine().run(records).to_dict()


def evaluate_cause_band(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a Cause Band fixture or an example containing cause_band_sidecar."""
    if not isinstance(payload, dict):
        raise ValueError("Cause Band payload must be an object")
    return evaluate_fixture(extract_fixture_payload(payload))
