import pytest

from cml.experimental.equilibrium import (
    CausalEquilibriumSnapshot,
    EquilibriumState,
    evaluate_causal_equilibrium,
)


def test_balanced_when_material_and_memory_refs_resolve() -> None:
    snapshot = CausalEquilibriumSnapshot(
        action_ref="action-1",
        supporting_refs=("support-1",),
        counter_refs=("counter-1",),
        recalled_memory_refs=("memory-1",),
        consolidation_source_refs=("support-1", "counter-1"),
        consolidation_preserved_refs=("counter-1", "support-1"),
        require_counterevidence=True,
    )

    result = evaluate_causal_equilibrium(
        snapshot,
        known_refs={"support-1", "counter-1", "memory-1"},
    )

    assert result.state is EquilibriumState.BALANCED
    assert result.balanced()
    assert result.findings == ()


def test_missing_counterevidence_is_indeterminate() -> None:
    snapshot = CausalEquilibriumSnapshot(
        action_ref="action-1",
        supporting_refs=("support-1",),
        require_counterevidence=True,
    )

    result = evaluate_causal_equilibrium(snapshot, known_refs={"support-1"})

    assert result.state is EquilibriumState.INDETERMINATE
    assert [finding.code for finding in result.findings] == [
        "CML-EQ-01-MISSING_COUNTEREVIDENCE"
    ]


def test_unresolved_recalled_memory_is_unstable() -> None:
    snapshot = CausalEquilibriumSnapshot(
        action_ref="action-1",
        supporting_refs=("support-1",),
        recalled_memory_refs=("memory-missing",),
    )

    result = evaluate_causal_equilibrium(snapshot, known_refs={"support-1"})

    assert result.state is EquilibriumState.UNSTABLE
    assert [finding.code for finding in result.findings] == [
        "CML-EQ-02-UNRESOLVED_MEMORY_INFLUENCE"
    ]
    assert result.findings[0].refs == ("memory-missing",)


def test_lost_consolidation_provenance_is_unstable() -> None:
    snapshot = CausalEquilibriumSnapshot(
        action_ref="action-1",
        supporting_refs=("support-1",),
        counter_refs=("counter-1",),
        consolidation_source_refs=("support-1", "counter-1"),
        consolidation_preserved_refs=("support-1",),
    )

    result = evaluate_causal_equilibrium(
        snapshot,
        known_refs={"support-1", "counter-1"},
    )

    assert result.state is EquilibriumState.UNSTABLE
    assert [finding.code for finding in result.findings] == [
        "CML-EQ-03-CONSOLIDATION_IMBALANCE"
    ]
    assert result.findings[0].refs == ("counter-1",)


def test_empty_checkpoint_is_indeterminate() -> None:
    result = evaluate_causal_equilibrium(
        CausalEquilibriumSnapshot(action_ref="action-1"),
        known_refs=set(),
    )

    assert result.state is EquilibriumState.INDETERMINATE
    assert [finding.code for finding in result.findings] == [
        "CML-EQ-04-INDETERMINATE_STATE"
    ]


def test_snapshot_rejects_duplicate_refs() -> None:
    with pytest.raises(ValueError, match="must not contain duplicates"):
        CausalEquilibriumSnapshot(
            action_ref="action-1",
            supporting_refs=("support-1", "support-1"),
        )
