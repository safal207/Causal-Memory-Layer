from __future__ import annotations

import json
from pathlib import Path

import pytest

from cml.integrations.information_quality import (
    CompletenessStatus,
    InformationQualityObservation,
    QualityReadiness,
    RelevanceStatus,
    SemanticTruthStatus,
    evaluate_information_quality,
)


FIXTURE = Path(__file__).parent / "fixtures" / "information_quality_v0.1.json"


def test_frozen_information_quality_fixture() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert payload["contract"] == "information_quality_v0.1"

    for case in payload["cases"]:
        observation = InformationQualityObservation(
            supporting_evidence=tuple(case["input"]["supporting_evidence"]),
            contradicting_evidence=tuple(case["input"]["contradicting_evidence"]),
            required_aspects=tuple(case["input"]["required_aspects"]),
            observed_aspects=tuple(case["input"]["observed_aspects"]),
            claim_aspects=tuple(case["input"]["claim_aspects"]),
        )
        result = evaluate_information_quality(observation)
        expected = case["expected"]

        assert result.semantic_truth.value == expected["semantic_truth"], case["id"]
        assert result.completeness.value == expected["completeness"], case["id"]
        assert result.relevance.value == expected["relevance"], case["id"]
        assert result.readiness.value == expected["readiness"], case["id"]
        assert list(result.reasons) == expected["reasons"], case["id"]


def test_ready_only_means_ready_for_separate_authority_check() -> None:
    result = evaluate_information_quality(
        InformationQualityObservation(
            supporting_evidence=("ev:1",),
            required_aspects=("permission",),
            observed_aspects=("permission",),
            claim_aspects=("permission",),
        )
    )

    assert result.readiness is QualityReadiness.READY
    assert result.ready_for_authority_check is True


def test_undefined_scope_fails_closed_to_review() -> None:
    result = evaluate_information_quality(
        InformationQualityObservation(supporting_evidence=("ev:1",))
    )

    assert result.semantic_truth is SemanticTruthStatus.SUPPORTED
    assert result.completeness is CompletenessStatus.UNRESOLVED
    assert result.relevance is RelevanceStatus.UNRESOLVED
    assert result.readiness is QualityReadiness.REVIEW
    assert result.reasons == (
        "completeness_scope_undefined",
        "relevance_scope_undefined",
    )


def test_observation_rejects_duplicate_dimension_entries() -> None:
    with pytest.raises(ValueError, match="required_aspects entries must be unique"):
        InformationQualityObservation(required_aspects=("amount", "amount"))


def test_observation_rejects_blank_entries() -> None:
    with pytest.raises(ValueError, match="claim_aspects entries must be non-empty strings"):
        InformationQualityObservation(claim_aspects=("",))
