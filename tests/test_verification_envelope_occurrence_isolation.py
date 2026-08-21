from __future__ import annotations

import json
from pathlib import Path

from cml.integrations.verification_envelope import issue_verification_envelope


FIXTURE = Path(__file__).parent / "fixtures" / "verification_envelope_v0.1.json"


def _payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_identical_content_keeps_content_identity_but_splits_occurrence_envelopes() -> None:
    payload = _payload()
    healthy = payload["healthy"]
    occurrence = payload["occurrence_isolation"]

    common = {
        "bound_content": healthy["bound_content"],
        "commitment_scope": tuple(healthy["commitment_scope"]),
        "fresh_through": healthy["fresh_through"],
        "execution_binding": healthy["execution_binding"],
    }

    envelope_a = issue_verification_envelope(
        occurrence_id=occurrence["content_occurrence_a"],
        **common,
    )
    envelope_b = issue_verification_envelope(
        occurrence_id=occurrence["content_occurrence_b"],
        **common,
    )

    assert envelope_a.content_commitment == envelope_b.content_commitment
    assert envelope_a.content_commitment == occurrence["expected_shared_content_sha256"]

    assert envelope_a.occurrence_id != envelope_b.occurrence_id
    assert envelope_a.envelope_commitment != envelope_b.envelope_commitment
    assert envelope_a.envelope_commitment == occurrence["expected_envelope_sha256_a"]
    assert envelope_b.envelope_commitment == occurrence["expected_envelope_sha256_b"]


def test_peer_occurrence_finding_is_recorded_as_limited_not_equivalent() -> None:
    finding = _payload()["peer_findings"][0]
    measurements = finding["reported_measurements"]

    assert finding["content_binding"] == "SUPPORTED"
    assert finding["occurrence_identity"] == "SUPPORTED"
    assert finding["envelope_binding"] == "SUPPORTED_WITH_LIMITATION"
    assert measurements["distinct_admission_index"] == measurements["recurring_probe_admissions"]
    assert measurements["distinct_decision_ref"] < measurements["issued_proof_rows_sampled"]
    assert "admission_index is not bound into decision_ref" in finding["limitation"]
