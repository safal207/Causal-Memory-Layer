import pytest

from cml.experimental.astra import (
    ActivationContext,
    AstraGene,
    AstraGenome,
    DefectKind,
    GenePhase,
    MutationKind,
    Provenance,
)


def test_activation_context_is_required_and_exclusion_aware() -> None:
    gene = AstraGene(
        gene_id="retry-safe",
        claim="Retry is safe only for idempotent operations",
        activation=ActivationContext(
            required_tags=frozenset({"idempotent"}),
            excluded_tags=frozenset({"revoked"}),
        ),
        evidence_refs=("proof:retry-policy",),
        provenance=Provenance.VERIFIED,
    )

    assert gene.is_active({"IDEMPOTENT", "payment"}) is True
    assert gene.is_active({"payment"}) is False
    assert gene.is_active({"idempotent", "revoked"}) is False


def test_mutation_genealogy_preserves_parent_and_delta() -> None:
    root = AstraGene(
        gene_id="belief-v1",
        claim="A causes B",
        evidence_refs=("evidence:v1",),
        phase=GenePhase.LEARN,
        provenance=Provenance.INFERRED,
        confidence=0.6,
    )
    genome = AstraGenome((root,)).mutate(
        "belief-v1",
        "belief-v2",
        MutationKind.REFINEMENT,
        note="condition C discovered",
        claim="A causes B when C is present",
        evidence_refs=("evidence:v1", "evidence:c"),
        confidence=0.85,
    )

    child = genome.get("belief-v2")
    assert child.parent_gene_id == "belief-v1"
    assert child.mutation_kind is MutationKind.REFINEMENT
    assert genome.lineage("belief-v2") == ("belief-v1", "belief-v2")
    assert genome.get("belief-v1").claim == "A causes B"


def test_verified_claim_requires_attached_evidence_to_be_trusted() -> None:
    detached = AstraGene(
        gene_id="detached",
        claim="This was verified",
        provenance=Provenance.VERIFIED,
    )
    bound = AstraGene(
        gene_id="bound",
        claim="This was verified",
        provenance=Provenance.VERIFIED,
        evidence_refs=("proof:exact-head",),
    )

    assert detached.trusted_claim is False
    assert bound.trusted_claim is True


def test_topological_defects_expose_missing_links_without_repairing() -> None:
    gene = AstraGene(
        gene_id="deploy",
        claim="Deploy is authorized",
        cause_ids=("approval-42",),
        action="deploy production",
    )
    genome = AstraGenome((gene,))

    defects = genome.detect_defects()
    kinds = {defect.kind for defect in defects}

    assert DefectKind.MISSING_EVIDENCE in kinds
    assert DefectKind.UNVERIFIED_ACTION in kinds
    assert DefectKind.DANGLING_CAUSE in kinds
    assert genome.get("deploy").outcome is None


def test_expected_effect_divergence_is_detected_deterministically() -> None:
    gene = AstraGene(
        gene_id="release",
        claim="Release should preserve availability",
        action="release v2",
        expected_effect="service available",
        outcome="service unavailable",
        evidence_refs=("trace:release",),
    )

    defects = AstraGenome((gene,)).detect_defects()

    assert [defect.kind for defect in defects] == [DefectKind.INTENT_EFFECT_DIVERGENCE]


def test_genealogy_cycle_is_visible_as_topological_defect() -> None:
    a = AstraGene(
        gene_id="a",
        claim="A",
        evidence_refs=("proof:a",),
        parent_gene_id="b",
        mutation_kind=MutationKind.REFINEMENT,
    )
    b = AstraGene(
        gene_id="b",
        claim="B",
        evidence_refs=("proof:b",),
        parent_gene_id="a",
        mutation_kind=MutationKind.REFINEMENT,
    )

    defects = AstraGenome((a, b)).detect_defects()

    assert {defect.gene_id for defect in defects if defect.kind is DefectKind.GENEALOGY_CYCLE} == {"a", "b"}
    with pytest.raises(ValueError, match="genealogy cycle"):
        AstraGenome((a, b)).lineage("a")
