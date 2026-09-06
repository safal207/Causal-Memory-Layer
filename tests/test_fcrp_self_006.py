from __future__ import annotations

import json
from pathlib import Path

from cml.experimental.focus_field import RecoveryAnchor, RecoveryQuery, recover
from cml.integrations.information_quality import (
    CompletenessStatus,
    InformationQualityResult,
    QualityReadiness,
    RelevanceStatus,
    SemanticTruthStatus,
)
from cml.integrations.memory_applicability import ApplicabilityResult, ApplicabilityStatus

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "benchmarks" / "experimental" / "fcrp-self-006.json"
SOURCE = ROOT / "cml" / "experimental" / "focus_field.py"


def _ready_quality() -> InformationQualityResult:
    return InformationQualityResult(
        semantic_truth=SemanticTruthStatus.SUPPORTED,
        completeness=CompletenessStatus.COMPLETE,
        relevance=RelevanceStatus.RELEVANT,
        readiness=QualityReadiness.READY,
        reasons=(),
    )


def test_fcrp_self_006_identifies_temporal_contract_drift() -> None:
    case = json.loads(CASE.read_text(encoding="utf-8"))

    assert case["caseId"] == "FCRP-SELF-006"
    assert case["divergence"]["firstMeaningfulDivergence"] == "N1"
    assert case["divergence"]["causePoint"] == "N1"
    assert case["divergence"]["selectedRefactorPoint"] == "N4"
    assert case["navigation"]["direction"] == "UP"
    assert case["expectedProtocolDecision"] == "PASS"


def test_fcrp_self_006_refactor_uses_current_cml_gate_outputs() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    # Reject the legacy RecoveryAnchor field itself without accidentally matching
    # the still-valid caller policy switch `require_verified: bool`.
    assert "\n    verified: bool" not in source
    assert "anchor.verified" not in source
    assert "ApplicabilityResult" in source
    assert "InformationQualityResult" in source
    assert "anchor.applicability.may_influence_action" in source
    assert "anchor.information_quality.ready_for_authority_check" in source
    assert "trusted_continuation" in source

    query = RecoveryQuery(
        concepts=frozenset({"recovery"}),
        minimum_score=0.0,
        require_verified=False,
    )
    stale = RecoveryAnchor(
        anchor_id="stale-context",
        concepts=frozenset({"recovery"}),
        evidence_refs=("evidence:stale",),
        applicability=ApplicabilityResult(
            ApplicabilityStatus.REVALIDATE,
            ("current-state-revalidation-required",),
        ),
        information_quality=_ready_quality(),
    )

    exploratory = recover(query, (stale,))
    assert exploratory.selected_anchor_id == "stale-context"
    assert exploratory.state == "reanchored_exploratory"
    assert exploratory.trusted_continuation is False

    strict_query = RecoveryQuery(
        concepts=frozenset({"recovery"}),
        minimum_score=0.0,
        require_verified=True,
    )
    current = RecoveryAnchor(
        anchor_id="current-context",
        concepts=frozenset({"recovery"}),
        evidence_refs=("evidence:current",),
        applicability=ApplicabilityResult(ApplicabilityStatus.MATCH, ()),
        information_quality=_ready_quality(),
    )

    trusted = recover(strict_query, (current,))
    assert trusted.selected_anchor_id == "current-context"
    assert trusted.state == "reanchored"
    assert trusted.trusted_continuation is True
