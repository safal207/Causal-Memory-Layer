"""Evaluate witness-issued one-shot read-token runtime evidence.

This module deliberately composes existing CML contracts instead of creating a
parallel status vocabulary. A token is issued outside the ledger, consumed at
the kernel read boundary, and then referenced by an application-authored
``CausalRecord``. The proof passes only when the external completion and the
persisted observation agree on both ``read_id`` and kernel object identity.

The follow-up read is a live negative control: no second token is issued, so the
same thread/fd must not inherit the first token after it was consumed.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cml.external_read_object_witness import (
    ExternalReadObjectBinding,
    ExternalReadObjectWitness,
)
from cml.external_read_witness import ExternalReadIdentityWitness
from cml.read_object_coverage import check_causal_record_read_object_coverage
from cml.read_observation_coverage import check_causal_record_read_observation_coverage
from cml.record import Action, CausalRecord

PASS = "PASS"
FAIL = "FAIL"
SCHEMA_VERSION = "cml-witness-issued-read-token-runtime-proof-v1"
DEFAULT_SOURCE_ID = "vcml-linux-ebpf:witness-issued-read-token"


def kernel_object_id(raw_device: int, inode: int) -> str:
    """Format the current vCML local kernel object correlation identity."""

    for label, value in (("raw_device", raw_device), ("inode", inode)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{label} must be a non-negative integer")
    return f"linux-inode:{raw_device}:{inode}"


def _normalize_event(event: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(event, Mapping):
        raise TypeError(f"{label} must be a mapping")

    normalized: dict[str, Any] = {}
    for key in ("fd", "device", "inode", "return_value", "started_ns"):
        value = event.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{label}.{key} must be an integer")
        normalized[key] = value

    if normalized["device"] < 0 or normalized["inode"] < 0:
        raise ValueError(f"{label} device/inode must be non-negative")

    for key in ("object_resolved", "token_present"):
        value = event.get(key)
        if value not in (0, 1, False, True):
            raise ValueError(f"{label}.{key} must be boolean-like")
        normalized[key] = bool(value)

    read_id = event.get("read_id")
    if read_id is not None and (not isinstance(read_id, str) or not read_id.strip()):
        raise ValueError(f"{label}.read_id must be null or a non-empty string")
    normalized["read_id"] = read_id
    normalized["object_id"] = kernel_object_id(
        normalized["device"], normalized["inode"]
    )
    return normalized


def evaluate_witness_issued_read_token_runtime_proof(
    *,
    scope_id: str,
    issued_read_id: str,
    bound_event: Mapping[str, Any],
    followup_event: Mapping[str, Any],
    ledger_record: CausalRecord,
    token_consumed: bool,
    source_id: str = DEFAULT_SOURCE_ID,
) -> dict[str, Any]:
    """Return PASS only for exact witness->kernel->ledger binding.

    The first event is the consequential read that received a witness-issued
    token. The second event is a negative control performed on the same fd with
    no new token. ``token_consumed`` is read directly from the BPF token map
    after execution.
    """

    for label, value in (
        ("scope_id", scope_id),
        ("issued_read_id", issued_read_id),
        ("source_id", source_id),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be a non-empty string")
    if not isinstance(ledger_record, CausalRecord):
        raise TypeError("ledger_record must be a CausalRecord")
    if not isinstance(token_consumed, bool):
        raise TypeError("token_consumed must be boolean")

    bound = _normalize_event(bound_event, label="bound_event")
    followup = _normalize_event(followup_event, label="followup_event")

    completed_ids: tuple[str, ...] = ()
    completed_bindings: tuple[ExternalReadObjectBinding, ...] = ()
    if (
        bound["return_value"] >= 0
        and bound["token_present"]
        and isinstance(bound["read_id"], str)
    ):
        completed_ids = (bound["read_id"],)
        if bound["object_resolved"]:
            completed_bindings = (
                ExternalReadObjectBinding(
                    read_id=bound["read_id"],
                    object_id=bound["object_id"],
                ),
            )

    identity_witness = ExternalReadIdentityWitness(
        source_id=source_id,
        scope_id=scope_id,
        completed_read_ids=completed_ids,
        available=True,
    )
    object_witness = ExternalReadObjectWitness(
        source_id=source_id,
        scope_id=scope_id,
        completed_bindings=completed_bindings,
        available=True,
    )

    identity_coverage = check_causal_record_read_observation_coverage(
        witness=identity_witness,
        ledger_scope_id=scope_id,
        records=[ledger_record],
    )
    object_coverage = check_causal_record_read_object_coverage(
        witness=object_witness,
        ledger_scope_id=scope_id,
        records=[ledger_record],
    )

    assertions = {
        "bound_read_completed_successfully": bound["return_value"] >= 0,
        "bound_kernel_object_resolved": bound["object_resolved"],
        "bound_event_carried_token": bound["token_present"],
        "witness_token_matches_issued_token": bound["read_id"] == issued_read_id,
        "token_consumed_at_use_boundary": token_consumed,
        "ledger_record_is_read": ledger_record.action == Action.READ,
        "ledger_token_matches_issued_token": ledger_record.read_id == issued_read_id,
        "identity_coverage_holds": identity_coverage.allows_applicability,
        "object_coverage_holds": object_coverage.allows_applicability,
        "followup_read_completed_successfully": followup["return_value"] >= 0,
        "followup_used_same_fd": followup["fd"] == bound["fd"],
        "followup_did_not_reuse_token": (
            not followup["token_present"] and followup["read_id"] is None
        ),
    }

    reasons: list[str] = []
    if not identity_coverage.allows_applicability:
        reasons.extend(identity_coverage.reasons)
    if not object_coverage.allows_applicability:
        reasons.extend(object_coverage.reasons)
    reasons.extend(name for name, holds in assertions.items() if not holds)
    reasons = sorted(set(reasons))

    return {
        "schema_version": SCHEMA_VERSION,
        "status": PASS if all(assertions.values()) else FAIL,
        "assertions": assertions,
        "reasons": reasons,
        "scope_id": scope_id,
        "source_id": source_id,
        "issued_read_id": issued_read_id,
        "token_consumed": token_consumed,
        "bound_event": bound,
        "followup_event": followup,
        "ledger_record": ledger_record.to_dict(),
        "identity_coverage": {
            "applicable": identity_coverage.applicable,
            "holds": identity_coverage.holds,
            "missing_read_ids": list(identity_coverage.missing_read_ids),
            "reasons": list(identity_coverage.reasons),
        },
        "object_coverage": {
            "applicable": object_coverage.applicable,
            "holds": object_coverage.holds,
            "missing_read_ids": list(object_coverage.missing_read_ids),
            "unbound_read_ids": list(object_coverage.unbound_read_ids),
            "mismatches": [
                {
                    "read_id": mismatch.read_id,
                    "expected_object_id": mismatch.expected_object_id,
                    "observed_object_id": mismatch.observed_object_id,
                }
                for mismatch in object_coverage.mismatches
            ],
            "reasons": list(object_coverage.reasons),
        },
    }
