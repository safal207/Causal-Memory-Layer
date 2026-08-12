from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cml.integrations.information_quality import (
    CompletenessStatus,
    EvidenceBinding,
    InformationQualityObservation,
    QualityReadiness,
    RelevanceStatus,
    SemanticTruthStatus,
    evaluate_information_quality,
)

FIXTURE = Path(__file__).parent / "fixtures" / "information_quality_v0.1.json"


def _strict_json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_strict_json(text: str) -> Any:
    """Parse JSON deterministically, rejecting duplicate keys at every level."""

    return json.loads(text, object_pairs_hook=_strict_json_object_pairs)


def _load_strict(path: Path) -> dict[str, Any]:
    payload = parse_strict_json(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _bindings(payload: list[dict[str, str]]) -> tuple[EvidenceBinding, ...]:
    return tuple(EvidenceBinding(**binding) for binding in payload)


def test_frozen_information_quality_fixture() -> None:
    payload = _load_strict(FIXTURE)
    assert payload["contract"] == "information_quality_v0.1"
    assert payload["evidence_binding_required"] is True

    for case in payload["cases"]:
        input_ = case["input"]
        observation = InformationQualityObservation(
            supporting_evidence=tuple(input_["supporting_evidence"]),
            contradicting_evidence=tuple(input_["contradicting_evidence"]),
            required_aspects=tuple(input_["required_aspects"]),
            observed_aspects=tuple(input_["observed_aspects"]),
            claim_aspects=tuple(input_["claim_aspects"]),
            evaluated_item_id=input_.get("evaluated_item_id"),
            source_record_id=input_.get("source_record_id"),
            accepted_state_token=input_.get("accepted_state_token"),
            evidence_bindings=_bindings(input_.get("evidence_bindings", [])),
        )
        result = evaluate_information_quality(observation)
        expected = case["expected"]

        assert result.semantic_truth.value == expected["semantic_truth"], case["id"]
        assert result.completeness.value == expected["completeness"], case["id"]
        assert result.relevance.value == expected["relevance"], case["id"]
        assert result.readiness.value == expected["readiness"], case["id"]
        assert list(result.reasons) == expected["reasons"], case["id"]


def test_frozen_fixture_parsing_rejects_duplicate_nested_key() -> None:
    text = (
        '{"contract": "information_quality_v0.1", "cases": [{"id": "a", '
        '"input": {}, "expected": {"readiness": "READY", "readiness": "EXCLUDE"}}]}'
    )

    with pytest.raises(ValueError, match="duplicate JSON key: readiness"):
        parse_strict_json(text)


def test_frozen_fixture_parsing_rejects_duplicate_top_level_key() -> None:
    text = '{"contract": "information_quality_v0.1", "cases": [], "cases": []}'

    with pytest.raises(ValueError, match="duplicate JSON key: cases"):
        parse_strict_json(text)


def _bound_observation(
    supporting_evidence: tuple[str, ...],
    contradicting_evidence: tuple[str, ...] = (),
    *,
    evaluated_item_id: str = "claim:payment-authorization",
    source_record_id: str = "record:payment-policy",
    accepted_state_token: str = "tok:state-v1",
) -> InformationQualityObservation:
    bindings = tuple(
        EvidenceBinding(
            evidence_id=evidence_id,
            evaluated_item_id=evaluated_item_id,
            source_record_id=source_record_id,
            accepted_state_token=accepted_state_token,
        )
        for evidence_id in (*supporting_evidence, *contradicting_evidence)
    )
    return InformationQualityObservation(
        supporting_evidence=supporting_evidence,
        contradicting_evidence=contradicting_evidence,
        required_aspects=("permission",),
        observed_aspects=("permission",),
        claim_aspects=("permission",),
        evaluated_item_id=evaluated_item_id,
        source_record_id=source_record_id,
        accepted_state_token=accepted_state_token,
        evidence_bindings=bindings,
    )


def test_ready_only_means_ready_for_separate_authority_check() -> None:
    result = evaluate_information_quality(
        _bound_observation(supporting_evidence=("ev:1",))
    )

    assert result.readiness is QualityReadiness.READY
    assert result.ready_for_authority_check is True


def test_undefined_scope_fails_closed_to_review() -> None:
    result = evaluate_information_quality(
        InformationQualityObservation(
            supporting_evidence=("ev:1",),
            evaluated_item_id="claim:payment-authorization",
            source_record_id="record:payment-policy",
            accepted_state_token="tok:state-v1",
            evidence_bindings=(
                EvidenceBinding(
                    evidence_id="ev:1",
                    evaluated_item_id="claim:payment-authorization",
                    source_record_id="record:payment-policy",
                    accepted_state_token="tok:state-v1",
                ),
            ),
        )
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


def test_observation_rejects_duplicate_evidence_binding_ids() -> None:
    binding = EvidenceBinding(
        evidence_id="ev:1",
        evaluated_item_id="claim:a",
        source_record_id="record:a",
        accepted_state_token="tok:state-v1",
    )
    with pytest.raises(ValueError, match="evidence_bindings entries must have unique evidence_id"):
        InformationQualityObservation(
            supporting_evidence=("ev:1",),
            evaluated_item_id="claim:a",
            source_record_id="record:a",
            accepted_state_token="tok:state-v1",
            evidence_bindings=(binding, binding),
        )


def test_observation_rejects_non_binding_evidence_entries() -> None:
    with pytest.raises(TypeError, match="evidence_bindings must contain only EvidenceBinding"):
        InformationQualityObservation(evidence_bindings=("ev:1",))


def test_evidence_binding_required_precondition() -> None:
    observation = InformationQualityObservation(
        supporting_evidence=("ev:1",),
        required_aspects=("permission",),
        observed_aspects=("permission",),
        claim_aspects=("permission",),
    )

    result = evaluate_information_quality(observation)

    assert result.readiness is QualityReadiness.EXCLUDE
    assert result.reasons == (
        "evidence_binding_missing:ev:1",
        "evidence_binding_scope_undeclared",
    )


def test_evidence_bound_to_other_item_never_ready() -> None:
    observation = InformationQualityObservation(
        supporting_evidence=("ev:1",),
        required_aspects=("permission",),
        observed_aspects=("permission",),
        claim_aspects=("permission",),
        evaluated_item_id="claim:payment-authorization",
        source_record_id="record:payment-policy",
        accepted_state_token="tok:state-v1",
        evidence_bindings=(
            EvidenceBinding(
                evidence_id="ev:1",
                evaluated_item_id="claim:OTHER-CLAIM",
                source_record_id="record:payment-policy",
                accepted_state_token="tok:state-v1",
            ),
        ),
    )

    result = evaluate_information_quality(observation)

    assert result.readiness is QualityReadiness.EXCLUDE
    assert result.reasons == ("evidence_binding_item_mismatch:ev:1",)


def test_evidence_bound_to_other_source_record_never_ready() -> None:
    observation = InformationQualityObservation(
        supporting_evidence=("ev:1",),
        required_aspects=("permission",),
        observed_aspects=("permission",),
        claim_aspects=("permission",),
        evaluated_item_id="claim:payment-authorization",
        source_record_id="record:payment-policy",
        accepted_state_token="tok:state-v1",
        evidence_bindings=(
            EvidenceBinding(
                evidence_id="ev:1",
                evaluated_item_id="claim:payment-authorization",
                source_record_id="record:OTHER-RECORD",
                accepted_state_token="tok:state-v1",
            ),
        ),
    )

    result = evaluate_information_quality(observation)

    assert result.readiness is QualityReadiness.EXCLUDE
    assert result.reasons == ("evidence_binding_source_mismatch:ev:1",)


def test_evidence_bound_to_stale_state_token_never_ready() -> None:
    observation = InformationQualityObservation(
        supporting_evidence=("ev:1",),
        required_aspects=("permission",),
        observed_aspects=("permission",),
        claim_aspects=("permission",),
        evaluated_item_id="claim:payment-authorization",
        source_record_id="record:payment-policy",
        accepted_state_token="tok:state-v2",
        evidence_bindings=(
            EvidenceBinding(
                evidence_id="ev:1",
                evaluated_item_id="claim:payment-authorization",
                source_record_id="record:payment-policy",
                accepted_state_token="tok:state-v1",
            ),
        ),
    )

    result = evaluate_information_quality(observation)

    assert result.readiness is QualityReadiness.REVIEW
    assert result.reasons == ("evidence_binding_state_token_mismatch:ev:1",)


def test_correctly_bound_evidence_preserves_supported_ready() -> None:
    result = evaluate_information_quality(
        _bound_observation(supporting_evidence=("ev:1",))
    )

    assert result.semantic_truth is SemanticTruthStatus.SUPPORTED
    assert result.readiness is QualityReadiness.READY
    assert result.reasons == ()
