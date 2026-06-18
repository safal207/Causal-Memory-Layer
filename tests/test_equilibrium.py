import pytest

from cml.experimental.equilibrium import (
    CausalEquilibriumSnapshot,
    EquilibriumFinding,
    EquilibriumSeverity,
    EquilibriumState,
    _finding_sort_key,
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


def test_multiple_same_code_findings_use_refs_lexicographic_order() -> None:
    snapshot = CausalEquilibriumSnapshot(
        action_ref="action-1",
        supporting_refs=("z-support",),
        unresolved_refs=("z-unresolved", "a-unresolved"),
    )

    result = evaluate_causal_equilibrium(snapshot, known_refs=set())

    assert result.state is EquilibriumState.INDETERMINATE
    assert [finding.refs for finding in result.findings] == [
        ("a-unresolved", "z-unresolved"),
        ("z-support",),
    ]


def test_canonical_sort_ranks_fail_before_warn_for_same_code() -> None:
    findings = [
        EquilibriumFinding(
            code="CML-EQ-X",
            severity=EquilibriumSeverity.WARN,
            message="warn",
        ),
        EquilibriumFinding(
            code="CML-EQ-X",
            severity=EquilibriumSeverity.FAIL,
            message="fail",
        ),
    ]

    findings.sort(key=_finding_sort_key)

    assert [finding.severity for finding in findings] == [
        EquilibriumSeverity.FAIL,
        EquilibriumSeverity.WARN,
    ]


def test_snapshot_rejects_duplicate_refs() -> None:
    with pytest.raises(ValueError, match="must not contain duplicates"):
        CausalEquilibriumSnapshot(
            action_ref="action-1",
            supporting_refs=("support-1", "support-1"),
        )
