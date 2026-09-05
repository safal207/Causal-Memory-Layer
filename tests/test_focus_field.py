from datetime import datetime, timedelta, timezone

from cml.experimental.focus_field import RecoveryAnchor, RecoveryQuery, recover
from cml.integrations.information_quality import (
    CompletenessStatus,
    InformationQualityResult,
    QualityReadiness,
    RelevanceStatus,
    SemanticTruthStatus,
)
from cml.integrations.memory_applicability import ApplicabilityResult, ApplicabilityStatus


def applicable() -> ApplicabilityResult:
    return ApplicabilityResult(ApplicabilityStatus.MATCH, ())


def stale() -> ApplicabilityResult:
    return ApplicabilityResult(
        ApplicabilityStatus.REVALIDATE,
        ("environment_mismatch:commit_sha",),
    )


def quality_ready() -> InformationQualityResult:
    return InformationQualityResult(
        semantic_truth=SemanticTruthStatus.SUPPORTED,
        completeness=CompletenessStatus.COMPLETE,
        relevance=RelevanceStatus.RELEVANT,
        readiness=QualityReadiness.READY,
        reasons=(),
    )


def quality_exclude() -> InformationQualityResult:
    return InformationQualityResult(
        semantic_truth=SemanticTruthStatus.SUPPORTED,
        completeness=CompletenessStatus.COMPLETE,
        relevance=RelevanceStatus.RELEVANT,
        readiness=QualityReadiness.EXCLUDE,
        reasons=("evidence_binding_item_mismatch:proof:stale",),
    )


def test_field_recovery_prefers_relevant_anchor_over_nearest_graph_position() -> None:
    now = datetime(2026, 8, 10, 10, 0, tzinfo=timezone.utc)
    query = RecoveryQuery(
        concepts=frozenset({"kv-cache", "recovery", "context"}),
        goal_tags=frozenset({"resume-inference"}),
        causal_tags=frozenset({"context-loss"}),
        phase="verification",
        timestamp=now,
        current_graph_depth=12,
        minimum_score=0.30,
    )
    near_but_wrong = RecoveryAnchor(
        anchor_id="node-11",
        concepts=frozenset({"logging"}),
        goal_tags=frozenset({"cleanup"}),
        causal_tags=frozenset({"timeout"}),
        phase="execution",
        timestamp=now,
        graph_depth=11,
    )
    farther_but_relevant = RecoveryAnchor(
        anchor_id="node-6",
        concepts=frozenset({"kv-cache", "context", "recovery"}),
        goal_tags=frozenset({"resume-inference"}),
        causal_tags=frozenset({"context-loss"}),
        phase="verification",
        timestamp=now - timedelta(minutes=5),
        unresolved=True,
        evidence_refs=("trace:42",),
        applicability=applicable(),
        information_quality=quality_ready(),
        graph_depth=6,
    )

    result = recover(query, [near_but_wrong, farther_but_relevant])

    assert result.state == "reanchored"
    assert result.selected_anchor_id == "node-6"
    assert result.rewind_steps_saved == 6
    assert result.ranked_candidates[0].anchor_id == "node-6"
    assert result.ranked_candidates[0].verification_ready is True
    assert result.trusted_continuation is True


def test_value_anchor_can_break_semantic_tie() -> None:
    query = RecoveryQuery(
        concepts=frozenset({"agent", "context"}),
        value_tags=frozenset({"preserve-user-intent", "minimize-replay"}),
        minimum_score=0.0,
    )
    same_words_wrong_value = RecoveryAnchor(
        anchor_id="semantic-only",
        concepts=frozenset({"agent", "context"}),
        value_tags=frozenset({"maximize-throughput"}),
    )
    aligned = RecoveryAnchor(
        anchor_id="value-aligned",
        concepts=frozenset({"agent", "context"}),
        value_tags=frozenset({"preserve-user-intent", "minimize-replay"}),
        evidence_refs=("proof:value-aligned",),
        applicability=applicable(),
        information_quality=quality_ready(),
    )

    result = recover(query, [same_words_wrong_value, aligned])

    assert result.selected_anchor_id == "value-aligned"
    assert result.ranked_candidates[0].value_overlap == 1.0
    assert result.state == "reanchored"
    assert result.trusted_continuation is True


def test_require_verified_filters_stale_and_quality_excluded_anchors() -> None:
    query = RecoveryQuery(
        concepts=frozenset({"goal"}),
        require_verified=True,
        minimum_score=0.0,
    )
    stale_anchor = RecoveryAnchor(
        anchor_id="a-stale",
        concepts=frozenset({"goal", "high-semantic-match"}),
        evidence_refs=("proof:stale",),
        applicability=stale(),
        information_quality=quality_ready(),
    )
    quality_excluded = RecoveryAnchor(
        anchor_id="b-excluded",
        concepts=frozenset({"goal"}),
        evidence_refs=("proof:excluded",),
        applicability=applicable(),
        information_quality=quality_exclude(),
    )
    current = RecoveryAnchor(
        anchor_id="c-current",
        concepts=frozenset({"goal"}),
        evidence_refs=("proof:current",),
        applicability=applicable(),
        information_quality=quality_ready(),
    )

    result = recover(query, [stale_anchor, quality_excluded, current])

    assert [candidate.anchor_id for candidate in result.ranked_candidates] == ["c-current"]
    assert result.selected_anchor_id == "c-current"
    assert result.state == "reanchored"
    assert result.trusted_continuation is True


def test_historical_anchor_can_be_explored_but_not_trusted_for_continuation() -> None:
    query = RecoveryQuery(
        concepts=frozenset({"incident", "recovery"}),
        require_verified=False,
        minimum_score=0.0,
    )
    historical = RecoveryAnchor(
        anchor_id="historical",
        concepts=frozenset({"incident", "recovery"}),
        evidence_refs=("proof:historical",),
        applicability=stale(),
        information_quality=quality_ready(),
    )

    result = recover(query, [historical])

    assert result.selected_anchor_id == "historical"
    assert result.state == "reanchored_exploratory"
    assert result.trusted_continuation is False
    assert result.ranked_candidates[0].verification_ready is False
    assert result.ranked_candidates[0].evidence_quality == 0.0


def test_missing_current_quality_gate_is_not_equivalent_to_verified() -> None:
    query = RecoveryQuery(
        concepts=frozenset({"goal"}),
        require_verified=True,
        minimum_score=0.0,
    )
    legacy_shaped = RecoveryAnchor(
        anchor_id="legacy-shaped",
        concepts=frozenset({"goal"}),
        evidence_refs=("proof:legacy",),
    )

    result = recover(query, [legacy_shaped])

    assert result.state == "defocus"
    assert result.selected_anchor_id is None
    assert result.trusted_continuation is False


def test_ties_are_deterministic_by_anchor_id() -> None:
    query = RecoveryQuery(
        concepts=frozenset({"context"}),
        minimum_score=0.0,
    )
    anchors = [
        RecoveryAnchor(anchor_id="z-anchor", concepts=frozenset({"context"})),
        RecoveryAnchor(anchor_id="a-anchor", concepts=frozenset({"context"})),
    ]

    result = recover(query, anchors)

    assert result.selected_anchor_id == "a-anchor"
    assert [candidate.anchor_id for candidate in result.ranked_candidates] == [
        "a-anchor",
        "z-anchor",
    ]
    assert result.state == "reanchored_exploratory"
    assert result.trusted_continuation is False


def test_low_confidence_field_remains_in_defocus() -> None:
    query = RecoveryQuery(
        concepts=frozenset({"causal-recovery"}),
        minimum_score=0.50,
    )
    weak = RecoveryAnchor(anchor_id="weak", concepts=frozenset({"unrelated"}))

    result = recover(query, [weak])

    assert result.state == "defocus"
    assert result.selected_anchor_id is None
    assert result.rewind_steps_saved is None
    assert result.trusted_continuation is False
