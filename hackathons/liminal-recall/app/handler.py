from __future__ import annotations

import base64
import hmac
import json
import os
import uuid
from typing import Any

from pydantic import ValidationError

from .embeddings import DEFAULT_DIMENSIONS, DEFAULT_MODEL_ID
from .engine import decide
from .models import DecisionRequest, MemoryCreate
from .store import CockroachMemoryStore, MemoryStore


_store: MemoryStore | None = None
_RUNTIME_INSTANCE_ID = str(uuid.uuid4())


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    method, path = _route(event)

    try:
        if method == "GET" and path == "/healthz":
            return _response(
                200,
                {
                    "status": "ok",
                    "service": "liminal-recall",
                    "database_configured": bool(os.getenv("DATABASE_URL")),
                    "semantic_recall_configured": bool(
                        os.getenv("DATABASE_URL")
                        and os.getenv("EMBEDDING_MODEL_ID", DEFAULT_MODEL_ID)
                    ),
                    "embedding_model": os.getenv("EMBEDDING_MODEL_ID", DEFAULT_MODEL_ID),
                    "embedding_dimensions": int(
                        os.getenv("EMBEDDING_DIMENSIONS", str(DEFAULT_DIMENSIONS))
                    ),
                },
            )

        if not _authorized(event):
            return _response(401, {"error": "unauthorized"})

        store = _get_store()

        if method == "POST" and path == "/memories":
            memory = MemoryCreate.model_validate(_body(event))
            created = store.create_memory(memory)
            return _response(201, created.model_dump(mode="json"))

        if method == "GET" and path == "/memories":
            query = event.get("queryStringParameters") or {}
            session_id = str(query.get("session_id") or "").strip()
            if not session_id:
                raise ValueError("session_id is required")
            limit = int(query.get("limit") or 20)
            memories = store.list_memories(session_id, limit=limit)
            return _response(
                200,
                {
                    "session_id": session_id,
                    "memories": [memory.model_dump(mode="json") for memory in memories],
                },
            )

        if method == "POST" and path == "/decisions":
            request = DecisionRequest.model_validate(_body(event))
            return _response(200, decide(store, request))

        return _response(404, {"error": "route_not_found"})
    except (ValueError, ValidationError, json.JSONDecodeError) as exc:
        return _response(400, {"error": "invalid_request", "detail": str(exc)})
    except Exception as exc:  # fail closed without leaking credentials or SQL text
        return _response(
            503,
            {
                "error": "memory_service_unavailable",
                "detail": type(exc).__name__,
                "decision": "HUMAN_REVIEW",
            },
        )


def set_store_for_tests(store: MemoryStore | None) -> None:
    global _store
    _store = store


def _get_store() -> MemoryStore:
    global _store
    if _store is None:
        _store = CockroachMemoryStore.from_env()
    return _store


def _authorized(event: dict[str, Any]) -> bool:
    expected = os.getenv("DEMO_API_KEY", "")
    if not expected:
        return True
    headers = {
        str(key).casefold(): str(value)
        for key, value in (event.get("headers") or {}).items()
    }
    supplied = headers.get("x-demo-key", "")
    return hmac.compare_digest(supplied, expected)


def _route(event: dict[str, Any]) -> tuple[str, str]:
    http = ((event.get("requestContext") or {}).get("http") or {})
    method = str(http.get("method") or event.get("httpMethod") or "GET").upper()
    path = str(event.get("rawPath") or event.get("path") or "/")
    return method, path.rstrip("/") or "/"


def _body(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("body")
    if body is None:
        return {}
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    if isinstance(body, dict):
        return body
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise ValueError("request body must be a JSON object")
    return parsed


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    response_body = dict(body)
    response_body.setdefault("runtime_instance_id", _RUNTIME_INSTANCE_ID)
    return {
        "statusCode": status_code,
        "headers": {
            "content-type": "application/json; charset=utf-8",
            "access-control-allow-origin": "*",
        },
        "body": json.dumps(response_body, ensure_ascii=False, default=str),
    }
