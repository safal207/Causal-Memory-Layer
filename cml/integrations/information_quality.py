"""Deterministic, evidence-bounded information quality gates.

These checks do not claim to prove metaphysical truth, world completeness, or
semantic relevance from raw text. They consume explicit, trusted observations
and answer three narrower questions before an information item reaches an
authority/action gate:

1. Is the claim supported, contradicted, or unresolved by authoritative evidence?
2. Is the declared decision scope complete with respect to required aspects?
3. Is the claim explicitly relevant to at least one required decision aspect?

Before any of these questions, every supporting/contradicting evidence
identifier must be explicitly bound to the evaluated item, source record, and
accepted immutable state token. Unbound or mismatched evidence fails closed and
can never produce READY.

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
    """Binds one evidence identifier to the exact evaluation context.

    Required binding dimensions:

    - ``evidence_id``: the identifier listed in ``supporting_evidence`` or
      ``contradicting_evidence``;
    - ``evaluated_item_id``: the item/claim the evidence actually supports or
      contradicts;
    - ``source_record_id``: the memory/source record the evidence comes from;
    - ``accepted_state_token``: the immutable state token the evidence was
      accepted against.

    The evaluator requires every declared evidence identifier to have a binding
    that matches the observation's declared identifiers. This prevents
    cross-claim or stale-state evidence substitution before READY.
    """

    evidence_id: str
    evaluated_item_id: str
    source_record_id: str
    accepted_state_token: str

    def __post_init__(self) -> None:
        for field_name, value in (
            ("evidence_id", self.evidence_id),
            ("evaluated_item_id", self.evaluated_item_id),
            ("source_record_id", self.source_record_id),
            ("accepted_state_token", self.accepted_state_token),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")


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

    ``evaluated_item_id``, ``source_record_id``, and ``accepted_state_token``
    declare the evaluation context. ``evidence_bindings`` binds every declared
    evidence identifier to that context; binding validation is a REQUIRED
    precondition and fails closed before semantic truth evaluation.
    """

    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()
    required_aspects: tuple[str, ...] = ()
    observed_aspects: tuple[str, ...] = ()
    claim_aspects: tuple[str, ...] = ()
    evaluated_item_id: str | None = None
    source_record_id: str | None = None
    accepted_state_token: str | None = None
    evidence_bindings: tuple[EvidenceBinding, ...] = ()

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

        bindings = self.evidence_bindings
        if not isinstance(bindings, tuple):
            raise TypeError("evidence_bindings must be a tuple")
        if any(not isinstance(binding, EvidenceBinding) for binding in bindings):
            raise TypeError("evidence_bindings must contain only EvidenceBinding")
        binding_ids = [binding.evidence_id for binding in bindings]
        if len(set(binding_ids)) != len(binding_ids):
            raise ValueError("evidence_bindings entries must have unique evidence_id")


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


def evidence_binding_reasons(
    observation: InformationQualityObservation,
) -> tuple[str, ...]:
    """Fail-closed binding validation performed before semantic truth evaluation.

    Every declared supporting/contradicting evidence identifier must be bound
    to the exact evaluated item, source record, and accepted immutable state
    token currently being evaluated. Unbound, mismatched, or undeclared
    evidence can never be treated as certified support for the current claim.
    """

    declared = (*observation.supporting_evidence, *observation.contradicting_evidence)
    if not declared:
        return ()

    by_id = {binding.evidence_id: binding for binding in observation.evidence_bindings}
    reasons: list[str] = []

    if any(
        value is None
        for value in (
            observation.evaluated_item_id,
            observation.source_record_id,
            observation.accepted_state_token,
        )
    ):
        reasons.append("evidence_binding_scope_undeclared")

    for evidence_id in declared:
        binding = by_id.get(evidence_id)
        if binding is None:
            reasons.append(f"evidence_binding_missing:{evidence_id}")
            continue
        if (
            observation.evaluated_item_id is not None
            and binding.evaluated_item_id != observation.evaluated_item_id
        ):
            reasons.append(f"evidence_binding_item_mismatch:{evidence_id}")
        if (
            observation.source_record_id is not None
            and binding.source_record_id != observation.source_record_id
        ):
            reasons.append(f"evidence_binding_source_mismatch:{evidence_id}")
        if (
            observation.accepted_state_token is not None
            and binding.accepted_state_token != observation.accepted_state_token
        ):
            reasons.append(f"evidence_binding_state_token_mismatch:{evidence_id}")

    declared_set = set(declared)
    for evidence_id in by_id:
        if evidence_id not in declared_set:
            reasons.append(f"evidence_binding_undeclared:{evidence_id}")

    return tuple(sorted(reasons))


def evaluate_information_quality(
    observation: InformationQualityObservation,
) -> InformationQualityResult:
    """Evaluate evidence support, bounded completeness, and task relevance.

    Evidence bindings are validated first and fail closed: unbound or
    mismatched evidence forces EXCLUDE (integrity failure) or REVIEW when the
    only mismatch is a stale accepted-state token.

    Precedence for the aggregate readiness result is intentionally conservative:

    - evidence binding integrity failures are excluded;
    - contradicted information is excluded;
    - explicitly irrelevant information is excluded from the current decision;
    - incomplete or unresolved dimensions require review;
    - only SUPPORTED + COMPLETE + RELEVANT is READY.

    ``READY`` means only "ready for a separate authority check". This function
    never grants permission to execute an action.
    """

    binding_reasons = evidence_binding_reasons(observation)
    truth_status, truth_reasons = _semantic_truth(observation)
    completeness_status, completeness_reasons = _completeness(observation)
    relevance_status, relevance_reasons = _relevance(observation)

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
        if all(
            reason.startswith("evidence_binding_state_token_mismatch:")
            for reason in binding_reasons
        ):
            readiness = QualityReadiness.REVIEW
        else:
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
