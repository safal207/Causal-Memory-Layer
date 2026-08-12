from __future__ import annotations

import json
from pathlib import Path

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


class DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate key in frozen fixture: {key}")
        result[key] = value
    return result


def _parse_frozen_fixture(text: str) -> dict[str, object]:
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)


def _load_frozen_fixture(path: Path) -> dict[str, object]:
    return _parse_frozen_fixture(path.read_text(encoding="utf-8"))


def test_frozen_information_quality_fixture() -> None:
    payload = _load_frozen_fixture(FIXTURE)
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


def test_frozen_fixture_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    fixture = tmp_path / "duplicate_keys.json"
    fixture.write_text(
        '{"contract":"information_quality_v0.1","cases":['
        '{"id":"dup","input":{"supporting_evidence":["ev:1"],'
        '"supporting_evidence":["ev:2"]}}]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate key in frozen fixture"):
        _load_frozen_fixture(fixture)


def _bound_supported_observation(
    evaluated_item_id: str,
    accepted_state_token: str,
    binding: EvidenceBinding,
) -> InformationQualityObservation:
    return InformationQualityObservation(
        supporting_evidence=(binding.evidence_id,),
        supporting_bindings=(binding,),
        evaluated_item_id=evaluated_item_id,
        accepted_state_token=accepted_state_token,
        required_aspects=("permission",),
        observed_aspects=("permission",),
        claim_aspects=("permission",),
    )


def test_correctly_bound_evidence_reaches_ready() -> None:
    result = evaluate_information_quality(
        _bound_supported_observation(
            evaluated_item_id="claim-1",
            accepted_state_token="state-token-1",
            binding=EvidenceBinding(
                evidence_id="ev:1",
                evaluated_item_id="claim-1",
                source_record_id="rec:1",
                accepted_state_token="state-token-1",
            ),
        )
    )

    assert result.readiness is QualityReadiness.READY
    assert result.ready_for_authority_check is True
    assert result.reasons == ()


def test_evidence_bound_to_other_item_never_ready() -> None:
    result = evaluate_information_quality(
        _bound_supported_observation(
            evaluated_item_id="claim-current",
            accepted_state_token="state-token-1",
            binding=EvidenceBinding(
                evidence_id="ev:1",
                evaluated_item_id="claim-other",
                source_record_id="rec:1",
                accepted_state_token="state-token-1",
            ),
        )
    )

    assert result.semantic_truth is SemanticTruthStatus.SUPPORTED
    assert result.readiness is QualityReadiness.EXCLUDE
    assert result.ready_for_authority_check is False
    assert "evidence_binding_item_mismatch:ev:1" in result.reasons


def test_evidence_bound_to_stale_state_token_never_ready() -> None:
    result = evaluate_information_quality(
        _bound_supported_observation(
            evaluated_item_id="claim-1",
            accepted_state_token="state-token-current",
            binding=EvidenceBinding(
                evidence_id="ev:1",
                evaluated_item_id="claim-1",
                source_record_id="rec:1",
                accepted_state_token="state-token-old",
            ),
        )
    )

    assert result.semantic_truth is SemanticTruthStatus.SUPPORTED
    assert result.readiness is QualityReadiness.EXCLUDE
    assert result.ready_for_authority_check is False
    assert "evidence_binding_state_mismatch:ev:1" in result.reasons


def test_bindings_must_bind_exactly_the_declared_evidence() -> None:
    with pytest.raises(ValueError, match="must bind exactly"):
        InformationQualityObservation(
            supporting_evidence=("ev:1", "ev:2"),
            supporting_bindings=(
                EvidenceBinding(
                    evidence_id="ev:1",
                    evaluated_item_id="claim-1",
                    source_record_id="rec:1",
                    accepted_state_token="state-token-1",
                ),
            ),
            evaluated_item_id="claim-1",
            accepted_state_token="state-token-1",
        )


def test_bindings_require_observation_level_identifiers() -> None:
    with pytest.raises(ValueError, match="evaluated_item_id is required"):
        InformationQualityObservation(
            supporting_evidence=("ev:1",),
            supporting_bindings=(
                EvidenceBinding(
                    evidence_id="ev:1",
                    evaluated_item_id="claim-1",
                    source_record_id="rec:1",
                    accepted_state_token="state-token-1",
                ),
            ),
            accepted_state_token="state-token-1",
        )
