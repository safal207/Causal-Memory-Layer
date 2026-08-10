"""Experimental Focus–Field Recovery Protocol for CML.

The protocol models context recovery as a switch from local graph traversal
("focus") to a bounded field of candidate recovery anchors ("defocus"),
followed by deterministic re-anchoring into the graph.

This module intentionally avoids embeddings and model calls. Its first goal is
measurement: make recovery decisions reproducible, inspectable, and testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable


@dataclass(frozen=True)
class RecoveryAnchor:
    """A stable graph location that may be selected during context recovery."""

    anchor_id: str
    concepts: frozenset[str]
    goal_tags: frozenset[str] = frozenset()
    causal_tags: frozenset[str] = frozenset()
    phase: str | None = None
    timestamp: datetime | None = None
    unresolved: bool = False
    verified: bool = False
    evidence_refs: tuple[str, ...] = ()
    graph_depth: int | None = None


@dataclass(frozen=True)
class RecoveryQuery:
    """Signals available when an agent leaves focus and searches the field."""

    concepts: frozenset[str]
    goal_tags: frozenset[str] = frozenset()
    causal_tags: frozenset[str] = frozenset()
    phase: str | None = None
    timestamp: datetime | None = None
    current_graph_depth: int | None = None
    require_verified: bool = False
    minimum_score: float = 0.35


@dataclass(frozen=True)
class CandidateScore:
    """Inspectable score decomposition for one recovery anchor."""

    anchor_id: str
    total: float
    concept_overlap: float
    goal_overlap: float
    causal_overlap: float
    phase_match: float
    temporal_proximity: float
    unresolved_bonus: float
    evidence_quality: float
    rewind_steps_saved: int | None


@dataclass(frozen=True)
class RecoveryDecision:
    """Result of a field-mediated context recovery attempt."""

    state: str
    selected_anchor_id: str | None
    score: float
    ranked_candidates: tuple[CandidateScore, ...]
    rewind_steps_saved: int | None


WEIGHTS = {
    "concept": 0.30,
    "goal": 0.20,
    "causal": 0.15,
    "phase": 0.10,
    "time": 0.10,
    "unresolved": 0.05,
    "evidence": 0.10,
}


def _normalized(values: Iterable[str]) -> frozenset[str]:
    return frozenset(value.strip().casefold() for value in values if value.strip())


def _jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    left = _normalized(left)
    right = _normalized(right)
    if not left or not right:
        return 0.0
    union = left | right
    return len(left & right) / len(union)


def _phase_match(query_phase: str | None, anchor_phase: str | None) -> float:
    if not query_phase or not anchor_phase:
        return 0.0
    return 1.0 if query_phase.strip().casefold() == anchor_phase.strip().casefold() else 0.0


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _temporal_proximity(query_time: datetime | None, anchor_time: datetime | None) -> float:
    """Return a bounded time affinity using one-hour buckets.

    Same-hour anchors score 1.0. Each additional hour halves affinity through
    1 / (1 + hours). The exact curve is intentionally simple and deterministic.
    """

    if query_time is None or anchor_time is None:
        return 0.0
    delta_seconds = abs((_as_utc(query_time) - _as_utc(anchor_time)).total_seconds())
    hours = delta_seconds / 3600.0
    return 1.0 / (1.0 + hours)


def _evidence_quality(anchor: RecoveryAnchor) -> float:
    if not anchor.verified:
        return 0.0
    return 1.0 if anchor.evidence_refs else 0.5


def _rewind_steps_saved(query: RecoveryQuery, anchor: RecoveryAnchor) -> int | None:
    if query.current_graph_depth is None or anchor.graph_depth is None:
        return None
    return max(0, query.current_graph_depth - anchor.graph_depth)


def score_candidate(query: RecoveryQuery, anchor: RecoveryAnchor) -> CandidateScore | None:
    """Score one anchor or reject it when the verification policy requires it."""

    if query.require_verified and not anchor.verified:
        return None

    concept_overlap = _jaccard(query.concepts, anchor.concepts)
    goal_overlap = _jaccard(query.goal_tags, anchor.goal_tags)
    causal_overlap = _jaccard(query.causal_tags, anchor.causal_tags)
    phase_match = _phase_match(query.phase, anchor.phase)
    temporal_proximity = _temporal_proximity(query.timestamp, anchor.timestamp)
    unresolved_bonus = 1.0 if anchor.unresolved else 0.0
    evidence_quality = _evidence_quality(anchor)

    total = (
        WEIGHTS["concept"] * concept_overlap
        + WEIGHTS["goal"] * goal_overlap
        + WEIGHTS["causal"] * causal_overlap
        + WEIGHTS["phase"] * phase_match
        + WEIGHTS["time"] * temporal_proximity
        + WEIGHTS["unresolved"] * unresolved_bonus
        + WEIGHTS["evidence"] * evidence_quality
    )

    return CandidateScore(
        anchor_id=anchor.anchor_id,
        total=round(total, 6),
        concept_overlap=round(concept_overlap, 6),
        goal_overlap=round(goal_overlap, 6),
        causal_overlap=round(causal_overlap, 6),
        phase_match=round(phase_match, 6),
        temporal_proximity=round(temporal_proximity, 6),
        unresolved_bonus=unresolved_bonus,
        evidence_quality=evidence_quality,
        rewind_steps_saved=_rewind_steps_saved(query, anchor),
    )


def recover(query: RecoveryQuery, anchors: Iterable[RecoveryAnchor]) -> RecoveryDecision:
    """Select a recovery anchor from a field without traversing graph edges.

    Candidates are ordered by descending score and then ``anchor_id`` so that
    ties are stable across runs. A candidate below ``minimum_score`` does not
    re-enter focus; the protocol remains in ``defocus``.
    """

    scored = [score for anchor in anchors if (score := score_candidate(query, anchor)) is not None]
    ranked = tuple(sorted(scored, key=lambda item: (-item.total, item.anchor_id)))

    if not ranked or ranked[0].total < query.minimum_score:
        return RecoveryDecision(
            state="defocus",
            selected_anchor_id=None,
            score=ranked[0].total if ranked else 0.0,
            ranked_candidates=ranked,
            rewind_steps_saved=None,
        )

    selected = ranked[0]
    return RecoveryDecision(
        state="reanchored",
        selected_anchor_id=selected.anchor_id,
        score=selected.total,
        ranked_candidates=ranked,
        rewind_steps_saved=selected.rewind_steps_saved,
    )
