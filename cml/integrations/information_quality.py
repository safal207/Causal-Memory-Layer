"""Deterministic, evidence-bounded information quality gates.

These checks do not claim to prove metaphysical truth, world completeness, or
semantic relevance from raw text. They consume explicit, trusted observations
and answer three narrower questions before an information item reaches an
authority/action gate:

1. Is the claim supported, contradicted, or unresolved by authoritative evidence?
2. Is the declared decision scope complete with respect to required aspects?
3. Is the claim explicitly relevant to at least one required decision aspect?

The module is intentionally separate from authority. Passing these quality gates
means only that the information is ready for an authority check; it does not
permit an action by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SemanticTruthStatus(str, Enum):
    """Evidence-bounded semantic support status."""

    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNRESOLVED = "UNRESOLVED"


class CompletenessStatus(str, Enum):
    """Completeness relative to an explicit decision schema."""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    UNRESOLVED = "UNRESOLVED"


class RelevanceStatus(str, Enum):
    """Relevance relative to an explicit decision scope."""

    RELEVANT = "RELEVANT"
    IRRELEVANT = "IRRELEVANT"
    UNRESOLVED = "UNRESOLVED"


class QualityReadiness(str, Enum):
    """Whether information may proceed to a separate authority check."""

    READY = "READY"
    REVIEW = "REVIEW"
    EXCLUDE = "EXCLUDE"


@dataclass(frozen=True)
class EvidenceBinding:
    """Binds one evidence identifier to the item and accepted state it was
    classified against.

    ``evaluated_item_id`` names the information item the evidence speaks to;
    ``source_record_id`` names the record the evidence came from;
    ``accepted_state_token`` is the token of the accepted state in effect when
    the evidence relationship was classified. A binding whose identifiers do
    not match the observation being evaluated is invalid and fails closed.
    """

    evidence_id: str
    evaluated_item_id: str
    source_record_id: str
    accepted_state_token: str

    def __post_init__(self) -> None:
        for field_name in (
            "evidence_id",
            "evaluated_item_id",
            "source_record_id",
            "accepted_state_token",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")


@dataclass(frozen=True)
class InformationQualityObservation:
    """Trusted observations used by the deterministic quality evaluator.

    ``supporting_evidence`` and ``contradicting_evidence`` contain identifiers
    of authoritative evidence already classified by an adapter or reviewer.

    ``supporting_bindings`` and ``contradicting_bindings`` bind each evidence
    identifier to the item and accepted-state token it was classified against.
    When bindings are supplied they must bind exactly the declared evidence
    identifiers, and the observation must declare ``evaluated_item_id`` and
    ``accepted_state_token``. Mismatched bindings fail closed to EXCLUDE and
    can never produce READY.

    ``required_aspects`` defines the bounded decision schema. Completeness is
    measured only against this declared set; the evaluator never claims global
    completeness.

    ``observed_aspects`` are aspects for which the current information bundle
    contains usable evidence. ``claim_aspects`` declare which decision aspects
    the claim is intended to inform.
    """

    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()
    supporting_bindings: tuple[EvidenceBinding, ...] = ()
    contradicting_bindings: tuple[EvidenceBinding, ...] = ()
    evaluated_item_id: str | None = None
    accepted_state_token: str | None = None
    required_aspects: tuple[str, ...] = ()
    observed_aspects: tuple[str, ...] = ()
    claim_aspects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in (
            "supporting_evidence",
            "contradicting_evidence",
            "required_aspects",
            "observed_aspects",
            "claim_aspects",
        ):
            values = getattr(self, field_name)
            if not isinstance(values, tuple):
                raise TypeError(f"{field_name} must be a tuple")
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(f"{field_name} entries must be non-empty strings")
            if len(set(values)) != len(values):
                raise ValueError(f"{field_name} entries must be unique")

        for field_name in ("supporting_bindings", "contradicting_bindings"):
            bindings = getattr(self, field_name)
            if not isinstance(bindings, tuple):
                raise TypeError(f"{field_name} must be a tuple")
            if any(
                not isinstance(binding, EvidenceBinding) for binding in bindings
            ):
                raise TypeError(
                    f"{field_name} entries must be EvidenceBinding instances"
                )
            evidence_ids = tuple(binding.evidence_id for binding in bindings)
            if len(set(evidence_ids)) != len(evidence_ids):
                raise ValueError(
                    f"{field_name} entries must bind unique evidence ids"
                )

        if self.supporting_bindings or self.contradicting_bindings:
            for identifier_name in ("evaluated_item_id", "accepted_state_token"):
                value = getattr(self, identifier_name)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(
                        f"{identifier_name} is required when evidence bindings "
                        "are supplied"
                    )
            for side, evidence_field, bindings_field in (
                ("supporting", "supporting_evidence", "supporting_bindings"),
                ("contradicting", "contradicting_evidence", "contradicting_bindings"),
            ):
                bindings = getattr(self, bindings_field)
                if bindings and set(getattr(self, evidence_field)) != {
                    binding.evidence_id for binding in bindings
                }:
                    raise ValueError(
                        f"{side} bindings must bind exactly the "
                        f"{side}_evidence entries"
                    )


@dataclass(frozen=True)
class InformationQualityResult:
    semantic_truth: SemanticTruthStatus
    completeness: CompletenessStatus
    relevance: RelevanceStatus
    readiness: QualityReadiness
    reasons: tuple[str, ...]

    @property
    def ready_for_authority_check(self) -> bool:
        """Quality readiness is necessary but not sufficient for action."""

        return self.readiness is QualityReadiness.READY


def _semantic_truth(
    observation: InformationQualityObservation,
) -> tuple[SemanticTruthStatus, tuple[str, ...]]:
    has_support = bool(observation.supporting_evidence)
    has_contradiction = bool(observation.contradicting_evidence)

    if has_support and has_contradiction:
        return SemanticTruthStatus.UNRESOLVED, ("truth_conflicting_evidence",)
    if has_support:
        return SemanticTruthStatus.SUPPORTED, ()
    if has_contradiction:
        return SemanticTruthStatus.CONTRADICTED, ("truth_contradicted",)
    return SemanticTruthStatus.UNRESOLVED, ("truth_no_authoritative_evidence",)


def _completeness(
    observation: InformationQualityObservation,
) -> tuple[CompletenessStatus, tuple[str, ...]]:
    if not observation.required_aspects:
        return CompletenessStatus.UNRESOLVED, ("completeness_scope_undefined",)

    observed = set(observation.observed_aspects)
    missing = sorted(set(observation.required_aspects) - observed)
    if missing:
        return (
            CompletenessStatus.INCOMPLETE,
            tuple(f"completeness_missing:{aspect}" for aspect in missing),
        )
    return CompletenessStatus.COMPLETE, ()


def _relevance(
    observation: InformationQualityObservation,
) -> tuple[RelevanceStatus, tuple[str, ...]]:
    if not observation.required_aspects:
        return RelevanceStatus.UNRESOLVED, ("relevance_scope_undefined",)
    if not observation.claim_aspects:
        return RelevanceStatus.UNRESOLVED, ("claim_scope_undeclared",)

    required = set(observation.required_aspects)
    if required.intersection(observation.claim_aspects):
        return RelevanceStatus.RELEVANT, ()
    return RelevanceStatus.IRRELEVANT, ("relevance_no_required_aspect",)


def _evidence_binding_consistency_reasons(
    observation: InformationQualityObservation,
) -> tuple[str, ...]:
    """Fail closed when evidence is bound to a different item or state token.

    Evidence classified against claim A (or under state token T1) must not be
    replayed against claim B (or under token T2). Any mismatch is decisive and
    forces the aggregate gate to EXCLUDE; READY is unreachable with mismatched
    evidence.
    """

    reasons: list[str] = []
    for binding in (
        *observation.supporting_bindings,
        *observation.contradicting_bindings,
    ):
        if binding.evaluated_item_id != observation.evaluated_item_id:
            reasons.append(f"evidence_binding_item_mismatch:{binding.evidence_id}")
        if binding.accepted_state_token != observation.accepted_state_token:
            reasons.append(f"evidence_binding_state_mismatch:{binding.evidence_id}")
    return tuple(sorted(reasons))


def evaluate_information_quality(
    observation: InformationQualityObservation,
) -> InformationQualityResult:
    """Evaluate evidence support, bounded completeness, and task relevance.

    Precedence for the aggregate readiness result is intentionally conservative:

    - mismatched evidence bindings are excluded (fail closed, never READY);
    - contradicted information is excluded;
    - explicitly irrelevant information is excluded from the current decision;
    - incomplete or unresolved dimensions require review;
    - only SUPPORTED + COMPLETE + RELEVANT is READY.

    ``READY`` means only "ready for a separate authority check". This function
    never grants permission to execute an action.
    """

    truth_status, truth_reasons = _semantic_truth(observation)
    completeness_status, completeness_reasons = _completeness(observation)
    relevance_status, relevance_reasons = _relevance(observation)
    binding_reasons = _evidence_binding_consistency_reasons(observation)

    reasons = tuple(
        sorted(
            (
                *truth_reasons,
                *completeness_reasons,
                *relevance_reasons,
                *binding_reasons,
            )
        )
    )

    if binding_reasons:
        readiness = QualityReadiness.EXCLUDE
    elif (
        truth_status is SemanticTruthStatus.CONTRADICTED
        or relevance_status is RelevanceStatus.IRRELEVANT
    ):
        readiness = QualityReadiness.EXCLUDE
    elif (
        truth_status is SemanticTruthStatus.UNRESOLVED
        or completeness_status is not CompletenessStatus.COMPLETE
        or relevance_status is RelevanceStatus.UNRESOLVED
    ):
        readiness = QualityReadiness.REVIEW
    else:
        readiness = QualityReadiness.READY

    return InformationQualityResult(
        semantic_truth=truth_status,
        completeness=completeness_status,
        relevance=relevance_status,
        readiness=readiness,
        reasons=reasons,
    )
