"""Portable serializer for CML Focus–Field Recovery v0.2 decisions.

This module exports the recovery decision as data without granting authority and
without importing RESONANCE or any downstream consumer.
"""

from __future__ import annotations

from typing import Any

from cml.experimental.focus_field import RecoveryDecision

SOURCE_CONTRACT = "cml.focus-field.recovery-decision.v0.2"


class FocusFieldExportError(ValueError):
    pass


def export_recovery_decision(
    decision: RecoveryDecision,
    *,
    source_revision: str,
) -> dict[str, Any]:
    """Serialize one recovery decision with an explicit advisory boundary."""

    if not isinstance(source_revision, str) or len(source_revision) != 40:
        raise FocusFieldExportError("source_revision must be a full 40-character Git SHA")
    try:
        int(source_revision, 16)
    except ValueError as exc:
        raise FocusFieldExportError("source_revision must be hexadecimal") from exc

    ranked = [
        {
            "anchor_id": item.anchor_id,
            "total": item.total,
            "concept_overlap": item.concept_overlap,
            "value_overlap": item.value_overlap,
            "goal_overlap": item.goal_overlap,
            "causal_overlap": item.causal_overlap,
            "phase_match": item.phase_match,
            "temporal_proximity": item.temporal_proximity,
            "unresolved_bonus": item.unresolved_bonus,
            "evidence_quality": item.evidence_quality,
            "verification_ready": item.verification_ready,
            "rewind_steps_saved": item.rewind_steps_saved,
        }
        for item in decision.ranked_candidates
    ]

    return {
        "source_contract": SOURCE_CONTRACT,
        "source_revision": source_revision,
        "state": decision.state,
        "selected_anchor_id": decision.selected_anchor_id,
        "score": decision.score,
        "rewind_steps_saved": decision.rewind_steps_saved,
        "trusted_continuation": decision.trusted_continuation,
        "ranked_candidates": ranked,
        "mode": "ADVISORY_ONLY",
        "authority_granted": False,
    }
