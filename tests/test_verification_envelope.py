from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from cml.integrations.verification_envelope import (
    CANONICALIZATION_PROFILE,
    canonicalize_verification_content,
    compute_envelope_commitment,
    content_commitment,
    envelope_binding_payload,
    issue_verification_envelope,
    verify_verification_envelope,
)

FIXTURE = Path(__file__).parent / "fixtures" / "verification_envelope_v0.1.json"


def _payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _healthy() -> tuple[dict, object]:
    healthy = _payload()["healthy"]
    envelope = issue_verification_envelope(
        occurrence_id=healthy["occurrence_id"],
        bound_content=healthy["bound_content"],
        commitment_scope=tuple(healthy["commitment_scope"]),
        fresh_through=healthy["fresh_through"],
        execution_binding=healthy["execution_binding"],
    )
    return healthy, envelope


def test_frozen_shared_vector_reproduces_both_binding_layers() -> None:
    payload = _payload()
    healthy = payload["healthy"]

    assert payload["canonicalization_profile"] == CANONICALIZATION_PROFILE
    assert canonicalize_verification_content(healthy["bound_content"]).decode() == healthy[
        "expected_canonical_utf8"
    ]
    assert content_commitment(healthy["bound_content"]) == healthy["expected_sha256"]

    envelope_payload = envelope_binding_payload(
        occurrence_id=healthy["occurrence_id"],
        content_commitment_value=healthy["expected_sha256"],
        commitment_scope=tuple(healthy["commitment_scope"]),
        canonicalization_profile=CANONICALIZATION_PROFILE,
        fresh_through=healthy["fresh_through"],
        execution_binding=healthy["execution_binding"],
        requires_use_time_revalidation=healthy["requires_use_time_revalidation"],
    )
    assert canonicalize_verification_content(envelope_payload).decode() == healthy[
        "expected_envelope_canonical_utf8"
    ]
    assert compute_envelope_commitment(
        occurrence_id=healthy["occurrence_id"],
        content_commitment_value=healthy["expected_sha256"],
        commitment_scope=tuple(healthy["commitment_scope"]),
        canonicalization_profile=CANONICALIZATION_PROFILE,
        fresh_through=healthy["fresh_through"],
        execution_binding=healthy["execution_binding"],
        requires_use_time_revalidation=healthy["requires_use_time_revalidation"],
    ) == healthy["expected_envelope_sha256"]

    _, envelope = _healthy()
    assert envelope.content_commitment == healthy["expected_sha256"]
    assert envelope.envelope_commitment == healthy["expected_envelope_sha256"]
    assert envelope.commitment_scope == tuple(healthy["commitment_scope"])
    assert envelope.requires_use_time_revalidation is healthy[
        "requires_use_time_revalidation"
    ]


def test_healthy_external_consumption_envelope_states_where_proof_stops() -> None:
    healthy, envelope = _healthy()

    result = verify_verification_envelope(
        envelope,
        healthy["bound_content"],
        expected_occurrence_id=healthy["occurrence_id"],
        required_scope=tuple(healthy["commitment_scope"]),
        required_fresh_through="consumption",
        require_execution_attestation=False,
    )

    assert result.valid is True
    assert result.reasons == ()
    assert result.reproduced_content_commitment == healthy["expected_sha256"]
    assert result.reproduced_envelope_commitment == healthy[
        "expected_envelope_sha256"
    ]
    assert result.execution_binding == "external"
    assert result.fresh_through == "consumption"
    assert result.requires_use_time_revalidation is True


def test_args_drift_breaks_content_binding() -> None:
    healthy, envelope = _healthy()
    drifted = json.loads(json.dumps(healthy["bound_content"]))
    drifted["args"]["amount_cents"] = 5001

    result = verify_verification_envelope(
        envelope,
        drifted,
        expected_occurrence_id=healthy["occurrence_id"],
        required_scope=tuple(healthy["commitment_scope"]),
        required_fresh_through="consumption",
        require_execution_attestation=False,
    )

    assert result.valid is False
    assert result.reasons == ("content_commitment_mismatch",)


def test_occurrence_identity_is_not_replaced_by_content_identity() -> None:
    healthy, envelope = _healthy()

    result = verify_verification_envelope(
        envelope,
        healthy["bound_content"],
        expected_occurrence_id="occ-venzx-0002",
        required_scope=tuple(healthy["commitment_scope"]),
        required_fresh_through="consumption",
        require_execution_attestation=False,
    )

    assert result.valid is False
    assert result.reasons == ("occurrence_mismatch",)


def test_occurrence_relabel_without_rebinding_breaks_envelope_commitment() -> None:
    healthy, envelope = _healthy()
    relabeled = replace(envelope, occurrence_id="occ-venzx-0002")

    result = verify_verification_envelope(
        relabeled,
        healthy["bound_content"],
        expected_occurrence_id="occ-venzx-0002",
        required_scope=tuple(healthy["commitment_scope"]),
        required_fresh_through="consumption",
        require_execution_attestation=False,
    )

    assert result.valid is False
    assert result.reasons == ("envelope_commitment_mismatch",)


def test_external_execution_binding_cannot_satisfy_execution_attestation() -> None:
    healthy, envelope = _healthy()

    result = verify_verification_envelope(
        envelope,
        healthy["bound_content"],
        expected_occurrence_id=healthy["occurrence_id"],
        required_scope=tuple(healthy["commitment_scope"]),
        required_fresh_through="consumption",
        require_execution_attestation=True,
    )

    assert result.valid is False
    assert result.reasons == ("execution_binding_insufficient",)


def test_consumption_freshness_cannot_imply_execution_freshness() -> None:
    healthy, envelope = _healthy()

    result = verify_verification_envelope(
        envelope,
        healthy["bound_content"],
        expected_occurrence_id=healthy["occurrence_id"],
        required_scope=tuple(healthy["commitment_scope"]),
        required_fresh_through="execution",
        require_execution_attestation=False,
    )

    assert result.valid is False
    assert result.reasons == ("freshness_insufficient",)


def test_execution_freshness_cannot_be_claimed_with_external_execution_binding() -> None:
    healthy = _payload()["healthy"]

    with pytest.raises(
        ValueError,
        match="fresh_through=execution requires execution_binding=attested",
    ):
        issue_verification_envelope(
            occurrence_id=healthy["occurrence_id"],
            bound_content=healthy["bound_content"],
            commitment_scope=tuple(healthy["commitment_scope"]),
            fresh_through="execution",
            execution_binding="external",
        )


def test_commitment_scope_must_name_exact_bound_content_fields() -> None:
    healthy = _payload()["healthy"]

    with pytest.raises(ValueError, match="exactly match bound_content fields"):
        issue_verification_envelope(
            occurrence_id=healthy["occurrence_id"],
            bound_content=healthy["bound_content"],
            commitment_scope=("tool",),
            fresh_through="consumption",
            execution_binding="external",
        )


def test_subset_rejects_values_that_need_full_jcs_before_claiming_interop() -> None:
    with pytest.raises(ValueError, match="floats are outside"):
        canonicalize_verification_content({"amount": 1.5})

    with pytest.raises(ValueError, match="string must be ASCII"):
        canonicalize_verification_content({"label": "café"})

    with pytest.raises(ValueError, match="printable ASCII"):
        canonicalize_verification_content({"label": "\x7f"})
