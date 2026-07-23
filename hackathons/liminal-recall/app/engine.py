from __future__ import annotations

import re
from typing import Any

from .models import DecisionRequest, MemoryCreate, MemoryRecord
from .store import MemoryStore


TOKEN_RE = re.compile(r"[\w-]+", re.UNICODE)


def decide(store: MemoryStore, request: DecisionRequest) -> dict[str, Any]:
    selected, memory_count, retrieval_mode = _recall_negative_outcomes(store, request)

    if selected:
        decision = "HUMAN_REVIEW"
        reason = "A relevant verified-negative outcome was recalled from persistent memory."
        parent_memory_id = selected[0].id
        confidence = max(memory.confidence for memory in selected)
    else:
        decision = "ALLOW_WITH_MONITORING"
        reason = "No relevant verified-negative outcome was found."
        parent_memory_id = None
        confidence = 0.6

    decision_memory = store.create_memory(
        MemoryCreate(
            session_id=request.session_id,
            kind="decision",
            content=f"{decision}: {request.proposed_action}",
            tags=request.tags,
            status=("review_required" if selected else "active"),
            confidence=confidence,
            parent_memory_id=parent_memory_id,
        )
    )

    return {
        "decision": decision,
        "reason": reason,
        "memory_ids": [memory.id for memory in selected],
        "decision_memory_id": decision_memory.id,
        "memory_count_considered": memory_count,
        "retrieval": {
            "mode": retrieval_mode,
            "memory_layer": "cockroachdb",
            "tool": (
                "distributed_vector_index"
                if retrieval_mode == "cockroachdb_vector_cosine"
                else "deterministic_token_overlap"
            ),
        },
        "execution": {
            "status": "NOT_EXECUTED",
            "authority": "advisory_only",
        },
    }


def _recall_negative_outcomes(
    store: MemoryStore,
    request: DecisionRequest,
) -> tuple[list[MemoryRecord], int, str]:
    semantic_search = getattr(store, "find_relevant_negative_outcomes", None)
    if callable(semantic_search):
        selected = semantic_search(
            request.session_id,
            request.proposed_action,
            request.tags,
            limit=3,
        )
        return selected, len(selected), "cockroachdb_vector_cosine"

    memories = store.list_memories(request.session_id, limit=100)
    query_tokens = _tokens(request.proposed_action, request.tags)
    matches: list[tuple[int, MemoryRecord]] = []
    for memory in memories:
        if memory.kind != "outcome" or memory.status.casefold() != "negative":
            continue
        overlap = len(query_tokens & _tokens(memory.content, memory.tags))
        if overlap > 0:
            matches.append((overlap, memory))

    matches.sort(key=lambda item: (item[0], item[1].confidence), reverse=True)
    return [memory for _, memory in matches[:3]], len(memories), "deterministic_token_overlap"


def _tokens(text: str, tags: list[str]) -> set[str]:
    values = TOKEN_RE.findall(text.casefold())
    return {value for value in [*values, *tags] if len(value) >= 3}
