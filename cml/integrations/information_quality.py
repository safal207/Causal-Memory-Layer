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
class InformationQualityObservation:
    """Trusted observations used by the deterministic quality evaluator.

    ``supporting_evidence`` and ``contradicting_evidence`` contain identifiers
    of authoritative evidence already classified by an adapter or reviewer.

    ``required_aspects`` defines the bounded decision schema. Completeness is
    measured only against this declared set; the evaluator never claims global
    completeness.

    ``observed_aspects`` are aspects for which the current information bundle
    contains usable evidence. ``claim_aspects`` declare which decision aspects
    the claim is intended to inform.
    """

    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()
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


def evaluate_information_quality(
    observation: InformationQualityObservation,
) -> InformationQualityResult:
    """Evaluate evidence support, bounded completeness, and task relevance.

    Precedence for the aggregate readiness result is intentionally conservative:

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

    reasons = tuple(
        sorted((*truth_reasons, *completeness_reasons, *relevance_reasons))
    )

    if (
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
