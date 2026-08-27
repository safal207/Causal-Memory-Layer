"""Exact per-read kernel-object coverage for persisted CML observations.

Read-id coverage proves that every independently completed read has a ledger
observation. Object coverage strengthens that invariant by requiring the same
read boundary to name the same kernel object on both sides.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from cml.external_read_object_witness import ExternalReadObjectWitness
from cml.record import Action, CausalRecord


@dataclass(frozen=True)
class ReadObjectMismatch:
    read_id: str
    expected_object_id: str
    observed_object_id: str


@dataclass(frozen=True)
class ReadObjectCoverageResult:
    applicable: bool
    holds: bool
    missing_read_ids: tuple[str, ...] = ()
    unbound_read_ids: tuple[str, ...] = ()
    mismatches: tuple[ReadObjectMismatch, ...] = ()
    reasons: tuple[str, ...] = ()

    @property
    def allows_applicability(self) -> bool:
        return self.applicable and self.holds


def _persisted_read_object_map(
    records: Iterable[CausalRecord],
) -> dict[str, str | None]:
    """Map persisted read-entry identities to optional kernel object identities.

    Only ``action == read`` participates. ``read_exit`` is deliberately excluded
    so the completion witness cannot establish its own ledger coverage simply by
    being stored next to the read observations it checks.
    """

    observed: dict[str, str | None] = {}
    for index, record in enumerate(records, start=1):
        if not isinstance(record, CausalRecord):
            raise TypeError(f"record {index} must be a CausalRecord")
        if record.action != Action.READ or record.read_id is None:
            continue
        if record.read_id in observed:
            raise ValueError(f"duplicate persisted read_id: {record.read_id}")

        object_id: str | None = None
        if isinstance(record.object, Mapping):
            candidate = record.object.get("object_id")
            if candidate is not None:
                if not isinstance(candidate, str) or not candidate.strip():
                    raise ValueError(
                        f"persisted read {record.read_id} has invalid object_id"
                    )
                object_id = candidate
        observed[record.read_id] = object_id
    return observed


def check_causal_record_read_object_coverage(
    *,
    witness: ExternalReadObjectWitness | None,
    ledger_scope_id: str,
    records: Iterable[CausalRecord],
) -> ReadObjectCoverageResult:
    """Require every successful external read to match one persisted object binding.

    The invariant is pair-wise, not count-based::

        for every (read_id, object_id) in external_completed_reads(scope):
            persisted_read_object[read_id] == object_id

    Numeric fd equality and pathname equality are intentionally insufficient.
    An fd can be reused and a pathname can be renamed/rebound. The reference
    ``object_id`` is captured from the kernel file object at ``sys_enter_read``.
    """

    if not isinstance(ledger_scope_id, str) or not ledger_scope_id.strip():
        raise ValueError("ledger_scope_id must be a non-empty string")

    observed = _persisted_read_object_map(records)

    if witness is None or not witness.available:
        return ReadObjectCoverageResult(
            applicable=False,
            holds=False,
            reasons=("external_object_witness_unavailable",),
        )

    reasons: list[str] = []
    if witness.scope_id != ledger_scope_id:
        reasons.append("witness_scope_mismatch")

    missing: list[str] = []
    unbound: list[str] = []
    mismatches: list[ReadObjectMismatch] = []

    for binding in witness.completed_bindings:
        if binding.read_id not in observed:
            missing.append(binding.read_id)
            continue

        observed_object_id = observed[binding.read_id]
        if observed_object_id is None:
            unbound.append(binding.read_id)
            continue

        if observed_object_id != binding.object_id:
            mismatches.append(
                ReadObjectMismatch(
                    read_id=binding.read_id,
                    expected_object_id=binding.object_id,
                    observed_object_id=observed_object_id,
                )
            )

    if missing:
        reasons.append("missing_read_observation")
    if unbound:
        reasons.append("missing_object_binding")
    if mismatches:
        reasons.append("object_identity_mismatch")

    return ReadObjectCoverageResult(
        applicable=True,
        holds=not reasons,
        missing_read_ids=tuple(missing),
        unbound_read_ids=tuple(unbound),
        mismatches=tuple(mismatches),
        reasons=tuple(sorted(reasons)),
    )
