"""Exact per-read coverage checks for independently witnessed completions.

Aggregate liveness answers whether the collector observed *something* when an
independent source saw reads. This module answers the stronger question: did
this ledger observe every independently identified successful read in the same
scope?
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from cml.external_read_witness import ExternalReadIdentityWitness


@dataclass(frozen=True)
class ReadObservationCoverageResult:
    """Result of exact external-read to ledger-observation reconciliation."""

    applicable: bool
    holds: bool
    externally_completed_read_ids: tuple[str, ...] = ()
    observed_read_ids: tuple[str, ...] = ()
    missing_read_ids: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    @property
    def allows_applicability(self) -> bool:
        return self.applicable and self.holds


def _normalize_read_ids(values: Iterable[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(values, start=1):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} item {index} must be a non-empty string")
        if value not in seen:
            normalized.append(value)
            seen.add(value)
    return tuple(normalized)


def check_read_observation_coverage(
    *,
    witness: ExternalReadIdentityWitness | None,
    ledger_scope_id: str,
    ledger_observation_read_ids: Iterable[str],
) -> ReadObservationCoverageResult:
    """Require every externally completed read id to exist in ledger observations.

    The invariant is set inclusion, not count equality::

        externally_completed_read_ids(scope) <= ledger_observation_read_ids(scope)

    Extra ledger observations do not make this particular check fail; they may
    require separate provenance or duplication checks. Failed external reads
    are absent from ``ExternalReadIdentityWitness.completed_read_ids`` and are
    therefore not required here. EOF completions are included by the adapter.
    """

    if not isinstance(ledger_scope_id, str) or not ledger_scope_id.strip():
        raise ValueError("ledger_scope_id must be a non-empty string")

    observed = _normalize_read_ids(
        ledger_observation_read_ids,
        label="ledger_observation_read_ids",
    )

    if witness is None or not witness.available:
        return ReadObservationCoverageResult(
            applicable=False,
            holds=False,
            observed_read_ids=observed,
            reasons=("external_identity_witness_unavailable",),
        )

    external = witness.completed_read_ids
    reasons: list[str] = []

    if witness.scope_id != ledger_scope_id:
        reasons.append("witness_scope_mismatch")

    observed_set = set(observed)
    missing = tuple(read_id for read_id in external if read_id not in observed_set)
    if missing:
        reasons.append("missing_read_observation")

    return ReadObservationCoverageResult(
        applicable=True,
        holds=not reasons,
        externally_completed_read_ids=external,
        observed_read_ids=observed,
        missing_read_ids=missing,
        reasons=tuple(sorted(reasons)),
    )
