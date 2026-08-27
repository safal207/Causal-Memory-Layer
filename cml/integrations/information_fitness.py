"""Compose memory applicability and information quality before authority checks.

This module answers one narrow question: is an information item fit to be handed
to a separate authority check?

It never authorizes an action. A positive result means only that upstream memory
applicability and information-quality gates are both ready enough for an
independent permission/authority decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .information_quality import InformationQualityResult, QualityReadiness
from .memory_applicability import ApplicabilityResult, ApplicabilityStatus


class InformationFitnessStatus(str, Enum):
    """Readiness of information to proceed to a separate authority check."""

    READY_FOR_AUTHORITY_CHECK = "READY_FOR_AUTHORITY_CHECK"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NOT_FIT = "NOT_FIT"


@dataclass(frozen=True)
class InformationFitnessResult:
    """Deterministic composition result for upstream information gates."""

    status: InformationFitnessStatus
    reasons: tuple[str, ...]

    @property
    def ready_for_authority_check(self) -> bool:
        return self.status is InformationFitnessStatus.READY_FOR_AUTHORITY_CHECK

    @property
    def authorizes_action(self) -> bool:
        """Information fitness never grants execution authority."""

        return False


_BLOCKING_APPLICABILITY = frozenset(
    {
        ApplicabilityStatus.REJECT,
        ApplicabilityStatus.UNRESOLVABLE,
        ApplicabilityStatus.ORPHAN,
        ApplicabilityStatus.DRIFT,
    }
)


def evaluate_information_fitness(
    *,
    applicability: ApplicabilityResult,
    quality: InformationQualityResult,
) -> InformationFitnessResult:
    """Compose current-state applicability and information-quality readiness.

    Precedence is fail-closed:

    NOT_FIT -> REVIEW_REQUIRED -> READY_FOR_AUTHORITY_CHECK

    Rules:
    - blocking applicability states are NOT_FIT;
    - quality EXCLUDE is NOT_FIT;
    - REVALIDATE or quality REVIEW requires review;
    - only MATCH + quality READY may proceed to the authority check.

    The returned result never authorizes an action.
    """

    reasons = tuple(
        sorted(
            (
                *(f"applicability:{reason}" for reason in applicability.reasons),
                *(f"quality:{reason}" for reason in quality.reasons),
            )
        )
    )

    if (
        applicability.status in _BLOCKING_APPLICABILITY
        or quality.readiness is QualityReadiness.EXCLUDE
    ):
        return InformationFitnessResult(InformationFitnessStatus.NOT_FIT, reasons)

    if (
        applicability.status is ApplicabilityStatus.REVALIDATE
        or quality.readiness is QualityReadiness.REVIEW
    ):
        return InformationFitnessResult(
            InformationFitnessStatus.REVIEW_REQUIRED,
            reasons,
        )

    if (
        applicability.status is ApplicabilityStatus.MATCH
        and quality.readiness is QualityReadiness.READY
    ):
        return InformationFitnessResult(
            InformationFitnessStatus.READY_FOR_AUTHORITY_CHECK,
            reasons,
        )

    # Defensive fail-closed fallback for future enum extensions.
    return InformationFitnessResult(
        InformationFitnessStatus.REVIEW_REQUIRED,
        (*reasons, "fitness_unmapped_state"),
    )
