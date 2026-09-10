"""Experimental ASTRA causal-genome primitives for CML.

ASTRA models a causal-memory episode as an inspectable ``AstraGene`` rather
than as a biological claim. The DNA/flower language is only an engineering
analogy for paired evidence, lineage, activation, and mutation semantics.

v0.1 intentionally stays deterministic and local:

- activation context decides when a stored gene is eligible to influence work;
- mutation genealogy preserves how a causal belief changed over time;
- complementary pairs expose unsupported claims and unverified actions; and
- topological-defect detection marks breaks in the causal structure instead of
  silently repairing them.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable


class GenePhase(str, Enum):
    OBSERVE = "observe"
    HYPOTHESIZE = "hypothesize"
    DECIDE = "decide"
    ACT = "act"
    VERIFY = "verify"
    LEARN = "learn"


class Provenance(str, Enum):
    OBSERVED = "observed"
    USER_PROVIDED = "user_provided"
    VERIFIED = "verified"
    INFERRED = "inferred"
    RECONSTRUCTED = "reconstructed"
    SIMULATED = "simulated"


class MutationKind(str, Enum):
    REFINEMENT = "refinement"
    CONTRADICTION = "contradiction"
    CONTEXT_SPLIT = "context_split"
    EVIDENCE_UPDATE = "evidence_update"
    SUPERSESSION = "supersession"


class DefectKind(str, Enum):
    MISSING_EVIDENCE = "missing_evidence"
    UNVERIFIED_ACTION = "unverified_action"
    INTENT_EFFECT_DIVERGENCE = "intent_effect_divergence"
    DANGLING_CAUSE = "dangling_cause"
    DANGLING_PARENT = "dangling_parent"
    GENEALOGY_CYCLE = "genealogy_cycle"


@dataclass(frozen=True)
class ActivationContext:
    """Context gate controlling whether a gene is eligible for activation."""

    required_tags: frozenset[str] = frozenset()
    excluded_tags: frozenset[str] = frozenset()

    def matches(self, current_tags: Iterable[str]) -> bool:
        normalized = _normalize_tags(current_tags)
        required = _normalize_tags(self.required_tags)
        excluded = _normalize_tags(self.excluded_tags)
        return required.issubset(normalized) and not bool(excluded & normalized)


@dataclass(frozen=True)
class AstraGene:
    """One inspectable causal-memory unit in the experimental ASTRA genome."""

    gene_id: str
    claim: str
    context_tags: frozenset[str] = frozenset()
    activation: ActivationContext = ActivationContext()
    cause_ids: tuple[str, ...] = ()
    intent: str | None = None
    action: str | None = None
    expected_effect: str | None = None
    outcome: str | None = None
    evidence_refs: tuple[str, ...] = ()
    counterfactuals: tuple[str, ...] = ()
    invariant_refs: tuple[str, ...] = ()
    phase: GenePhase = GenePhase.OBSERVE
    provenance: Provenance = Provenance.OBSERVED
    confidence: float = 1.0
    parent_gene_id: str | None = None
    mutation_kind: MutationKind | None = None
    mutation_note: str | None = None

    def __post_init__(self) -> None:
        if not self.gene_id.strip():
            raise ValueError("gene_id must be non-empty")
        if not self.claim.strip():
            raise ValueError("claim must be non-empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if self.parent_gene_id is None and self.mutation_kind is not None:
            raise ValueError("mutation_kind requires parent_gene_id")
        if self.parent_gene_id is not None and self.mutation_kind is None:
            raise ValueError("parent_gene_id requires mutation_kind")

    def is_active(self, current_tags: Iterable[str]) -> bool:
        """Return whether runtime context satisfies this gene's activation gate."""

        return self.activation.matches(current_tags)

    @property
    def trusted_claim(self) -> bool:
        """Verified provenance is trusted only when evidence remains attached."""

        return self.provenance is Provenance.VERIFIED and bool(self.evidence_refs)


@dataclass(frozen=True)
class TopologicalDefect:
    defect_id: str
    kind: DefectKind
    gene_id: str
    detail: str


@dataclass(frozen=True)
class AstraGenome:
    """Immutable collection of ASTRA genes with deterministic lineage helpers."""

    genes: tuple[AstraGene, ...] = ()

    def __post_init__(self) -> None:
        ids = [gene.gene_id for gene in self.genes]
        if len(ids) != len(set(ids)):
            raise ValueError("gene_id values must be unique")

    def get(self, gene_id: str) -> AstraGene:
        for gene in self.genes:
            if gene.gene_id == gene_id:
                return gene
        raise KeyError(gene_id)

    def active_genes(self, current_tags: Iterable[str]) -> tuple[AstraGene, ...]:
        tags = tuple(current_tags)
        return tuple(gene for gene in self.genes if gene.is_active(tags))

    def mutate(
        self,
        parent_gene_id: str,
        child_gene_id: str,
        kind: MutationKind,
        *,
        note: str | None = None,
        **changes: object,
    ) -> "AstraGenome":
        """Create a child gene while retaining a deterministic parent link."""

        if any(gene.gene_id == child_gene_id for gene in self.genes):
            raise ValueError(f"duplicate child_gene_id: {child_gene_id}")
        forbidden = {"gene_id", "parent_gene_id", "mutation_kind", "mutation_note"}
        overlap = forbidden & set(changes)
        if overlap:
            raise ValueError(f"mutation cannot override lineage fields: {sorted(overlap)}")

        parent = self.get(parent_gene_id)
        child = replace(
            parent,
            gene_id=child_gene_id,
            parent_gene_id=parent_gene_id,
            mutation_kind=kind,
            mutation_note=note,
            **changes,
        )
        return AstraGenome((*self.genes, child))

    def lineage(self, gene_id: str) -> tuple[str, ...]:
        """Return root-to-gene mutation lineage, rejecting broken/cyclic ancestry."""

        genes_by_id = {gene.gene_id: gene for gene in self.genes}
        lineage: list[str] = []
        seen: set[str] = set()
        current_id: str | None = gene_id

        while current_id is not None:
            if current_id in seen:
                raise ValueError(f"genealogy cycle at {current_id}")
            seen.add(current_id)
            current = genes_by_id.get(current_id)
            if current is None:
                raise ValueError(f"missing lineage gene: {current_id}")
            lineage.append(current_id)
            current_id = current.parent_gene_id

        return tuple(reversed(lineage))

    def detect_defects(self) -> tuple[TopologicalDefect, ...]:
        """Return stable, explicit defects without mutating or repairing the genome."""

        genes_by_id = {gene.gene_id: gene for gene in self.genes}
        defects: list[TopologicalDefect] = []

        for gene in self.genes:
            if not gene.evidence_refs:
                defects.append(_defect(gene, DefectKind.MISSING_EVIDENCE, "claim has no evidence_refs"))
            if gene.action is not None and gene.outcome is None:
                defects.append(_defect(gene, DefectKind.UNVERIFIED_ACTION, "action has no observed outcome"))
            if (
                gene.expected_effect is not None
                and gene.outcome is not None
                and _normalize_text(gene.expected_effect) != _normalize_text(gene.outcome)
            ):
                defects.append(
                    _defect(
                        gene,
                        DefectKind.INTENT_EFFECT_DIVERGENCE,
                        "observed outcome differs from expected_effect",
                    )
                )
            for cause_id in gene.cause_ids:
                if cause_id not in genes_by_id:
                    defects.append(
                        _defect(gene, DefectKind.DANGLING_CAUSE, f"missing cause gene: {cause_id}")
                    )
            if gene.parent_gene_id is not None and gene.parent_gene_id not in genes_by_id:
                defects.append(
                    _defect(
                        gene,
                        DefectKind.DANGLING_PARENT,
                        f"missing parent gene: {gene.parent_gene_id}",
                    )
                )

        for gene in self.genes:
            if _has_genealogy_cycle(gene.gene_id, genes_by_id):
                defects.append(_defect(gene, DefectKind.GENEALOGY_CYCLE, "mutation ancestry contains a cycle"))

        unique = {(item.defect_id, item.kind): item for item in defects}
        return tuple(sorted(unique.values(), key=lambda item: (item.gene_id, item.kind.value, item.defect_id)))


def _normalize_tags(values: Iterable[str]) -> frozenset[str]:
    return frozenset(value.strip().casefold() for value in values if value.strip())


def _normalize_text(value: str) -> str:
    return " ".join(value.split()).casefold()


def _defect(gene: AstraGene, kind: DefectKind, detail: str) -> TopologicalDefect:
    return TopologicalDefect(
        defect_id=f"ASTRA-{gene.gene_id}-{kind.value}",
        kind=kind,
        gene_id=gene.gene_id,
        detail=detail,
    )


def _has_genealogy_cycle(gene_id: str, genes_by_id: dict[str, AstraGene]) -> bool:
    seen: set[str] = set()
    current_id: str | None = gene_id
    while current_id is not None:
        if current_id in seen:
            return True
        seen.add(current_id)
        current = genes_by_id.get(current_id)
        if current is None:
            return False
        current_id = current.parent_gene_id
    return False
