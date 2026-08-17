"""Store-level preconditions that must hold before memory applicability runs.

These checks deliberately sit outside ``memory_applicability``. They answer
whether the observation/store boundary is healthy enough for a record-level
applicability question to be meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass

from cml.external_read_witness import ExternalReadWitness


@dataclass(frozen=True)
class AdmissibilityPreconditionResult:
    """Result for the pre-applicability boundary.

    ``applicable`` means the precondition itself had enough independent evidence
    to run. ``holds`` means the checked invariants passed. Applicability should
    proceed only when both are true.
    """

    applicable: bool
    holds: bool
    reasons: tuple[str, ...] = ()

    @property
    def allows_applicability(self) -> bool:
        return self.applicable and self.holds


def check_admissibility_preconditions(
    *,
    witness: ExternalReadWitness | None,
    ledger_observations: int,
    identifier_written: str | None = None,
    identifier_queried: str | None = None,
) -> AdmissibilityPreconditionResult:
    """Check independent liveness and key-agreement invariants.

    Invariants:

    * ``external_reads > 0 => ledger_observations > 0``
    * ``identifier_written == identifier_queried`` when both are supplied

    No ``ApplicabilityStatus`` is created here; store-level failures remain a
    separate boundary from record-level applicability.
    """

    if not isinstance(ledger_observations, int) or isinstance(ledger_observations, bool):
        raise TypeError("ledger_observations must be an integer")
    if ledger_observations < 0:
        raise ValueError("ledger_observations must be non-negative")

    if witness is None or not witness.available:
        return AdmissibilityPreconditionResult(
            applicable=False,
            holds=False,
            reasons=("external_witness_unavailable",),
        )

    reasons: list[str] = []

    if witness.reads_count > 0 and ledger_observations == 0:
        reasons.append("observation_channel_missing")

    if identifier_written is not None and identifier_queried is not None:
        if identifier_written != identifier_queried:
            reasons.append("identifier_mismatch")

    if reasons:
        return AdmissibilityPreconditionResult(
            applicable=True,
            holds=False,
            reasons=tuple(sorted(reasons)),
        )

    return AdmissibilityPreconditionResult(
        applicable=True,
        holds=True,
        reasons=(),
    )
