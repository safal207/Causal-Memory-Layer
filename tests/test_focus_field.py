from datetime import datetime, timedelta, timezone

from cml.experimental.focus_field import RecoveryAnchor, RecoveryQuery, recover


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
        verified=True,
        evidence_refs=("trace:42",),
        graph_depth=6,
    )

    result = recover(query, [near_but_wrong, farther_but_relevant])

    assert result.state == "reanchored"
    assert result.selected_anchor_id == "node-6"
    assert result.rewind_steps_saved == 6
    assert result.ranked_candidates[0].anchor_id == "node-6"


def test_require_verified_filters_unverified_anchor() -> None:
    query = RecoveryQuery(
        concepts=frozenset({"goal"}),
        require_verified=True,
        minimum_score=0.0,
    )
    unverified = RecoveryAnchor(
        anchor_id="a",
        concepts=frozenset({"goal"}),
        verified=False,
    )
    verified = RecoveryAnchor(
        anchor_id="b",
        concepts=frozenset({"goal"}),
        verified=True,
        evidence_refs=("proof:1",),
    )

    result = recover(query, [unverified, verified])

    assert [candidate.anchor_id for candidate in result.ranked_candidates] == ["b"]
    assert result.selected_anchor_id == "b"


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
