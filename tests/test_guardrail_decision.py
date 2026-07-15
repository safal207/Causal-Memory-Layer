from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from cml.integrations.guardrail_decision import (
    GUARDRAIL_DECISION_SCHEMA,
    GuardrailDecisionClaimsV1,
    GuardrailDecisionV1,
    canonical_guardrail_decision_json,
    derive_guardrail_decision_id,
    guardrail_decision_from_mapping,
    issue_guardrail_decision,
    load_guardrail_decision_json,
    verify_guardrail_decision,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests/vectors/guardrail_decision_v1"
BASELINE_ID = "0152b2fdd53a315e4a2ea6c48cd79f9e076675354537e0efb5fad9f40295fe09"


def _kwargs() -> dict[str, str]:
    return {
        "request_digest": "11" * 32,
        "verdict": "ALLOW",
        "reason_code": "CML-GUARDRAIL-POLICY-ALLOW",
        "provider_id": "crew-policy-provider",
        "policy_digest": "22" * 32,
        "authorization_source_digest": "33" * 32,
        "issued_at": "2026-07-15T12:00:00.000Z",
        "expires_at": "2026-07-15T12:05:00.000Z",
    }


def _decision(**updates: object) -> GuardrailDecisionV1:
    values: dict[str, object] = _kwargs()
    values.update(updates)
    return issue_guardrail_decision(**values)


def _verification_time() -> datetime:
    return datetime(2026, 7, 15, 12, 1, tzinfo=timezone.utc)


def test_baseline_decision_id_is_stable_and_recomputable() -> None:
    decision = _decision()

    assert decision.schema_version == GUARDRAIL_DECISION_SCHEMA
    assert decision.decision_id == BASELINE_ID
    assert derive_guardrail_decision_id(decision.claims) == BASELINE_ID
    assert verify_guardrail_decision(decision, now=_verification_time()).passed()


def test_canonical_preimage_is_compact_sorted_and_contains_expiry() -> None:
    canonical = canonical_guardrail_decision_json(_decision().claims)

    assert " " not in canonical
    assert canonical.startswith('{"claims":{')
    assert '"expires_at":"2026-07-15T12:05:00.000Z"' in canonical
    assert canonical.endswith(
        f'"verdict":"ALLOW"}},"schema_version":"{GUARDRAIL_DECISION_SCHEMA}"}}'
    )


def test_extending_expiry_requires_a_new_decision_id() -> None:
    original = _decision(expires_at="2026-07-15T12:05:00.000Z")
    extended = _decision(expires_at="2026-07-15T12:10:00.000Z")

    assert original.decision_id == BASELINE_ID
    assert extended.decision_id == (
        "5fbfc3dbcf8c5c8d28bc79897936be7b449c6e69ca32c6ba89cba83f81f213fa"
    )
    assert original.decision_id != extended.decision_id


def test_policy_graph_verdict_and_reason_changes_mint_new_ids() -> None:
    baseline = _decision()
    mutations = {
        "policy": _decision(policy_digest="44" * 32),
        "graph": _decision(authorization_source_digest="55" * 32),
        "verdict": _decision(verdict="DENY"),
        "reason": _decision(reason_code="CML-GUARDRAIL-POLICY-DENY"),
    }

    assert {item.decision_id for item in mutations.values()}.isdisjoint(
        {baseline.decision_id}
    )
    assert len({item.decision_id for item in mutations.values()}) == len(mutations)


def test_proof_sidecar_does_not_change_identity_but_changes_value_equality() -> None:
    plain = _decision()
    with_proof = _decision(
        proof={
            "signature": "demo-signature",
            "anchors": ["ledger:1", "log:2"],
        }
    )

    assert plain.decision_id == with_proof.decision_id
    assert plain.claims == with_proof.claims
    assert plain.same_authoritative_identity(with_proof)
    assert plain != with_proof
    assert with_proof.to_mapping()["proof"] == {
        "signature": "demo-signature",
        "anchors": ["ledger:1", "log:2"],
    }
    with pytest.raises(TypeError):
        with_proof.proof["signature"] = "mutated"
    with pytest.raises(TypeError):
        hash(plain)
    with pytest.raises(TypeError):
        hash(with_proof)


def test_different_proofs_are_distinct_values_with_same_authoritative_identity() -> None:
    first = _decision(proof={"signature": "first"})
    second = _decision(proof={"signature": "second"})

    assert first != second
    assert first.same_authoritative_identity(second)
    assert first.decision_id == second.decision_id


def test_tampered_expiry_with_reused_id_fails_verification() -> None:
    baseline = _decision()
    extended_claims = replace(
        baseline.claims,
        expires_at="2026-07-15T12:10:00.000Z",
    )
    tampered = GuardrailDecisionV1(
        decision_id=baseline.decision_id,
        claims=extended_claims,
    )

    result = verify_guardrail_decision(tampered, now=_verification_time())

    assert not result.passed()
    assert result.expected_decision_id == (
        "5fbfc3dbcf8c5c8d28bc79897936be7b449c6e69ca32c6ba89cba83f81f213fa"
    )
    assert [finding.code for finding in result.findings] == [
        "CML-GUARDRAIL-DECISION-ID-MISMATCH"
    ]


def test_expired_and_not_yet_valid_decisions_fail_closed() -> None:
    decision = _decision()

    before = verify_guardrail_decision(
        decision,
        now=datetime(2026, 7, 15, 11, 59, 59, tzinfo=timezone.utc),
    )
    expired = verify_guardrail_decision(
        decision,
        now=datetime(2026, 7, 15, 12, 5, tzinfo=timezone.utc),
    )

    assert [finding.code for finding in before.findings] == [
        "CML-GUARDRAIL-DECISION-NOT-YET-VALID"
    ]
    assert [finding.code for finding in expired.findings] == [
        "CML-GUARDRAIL-DECISION-EXPIRED"
    ]


def test_json_key_order_does_not_change_identity() -> None:
    decision = _decision()
    payload = decision.to_mapping()
    reordered = {
        "claims": dict(reversed(list(payload["claims"].items()))),
        "decision_id": payload["decision_id"],
        "schema_version": payload["schema_version"],
    }

    parsed = load_guardrail_decision_json(json.dumps(reordered))

    assert parsed.decision_id == decision.decision_id
    assert derive_guardrail_decision_id(parsed.claims) == decision.decision_id


def test_duplicate_json_keys_are_rejected() -> None:
    text = (
        '{"schema_version":"cml-guardrail-decision-v1",'
        f'"decision_id":"{BASELINE_ID}",'
        '"decision_id":"' + ("ff" * 32) + '",'
        '"claims":{}}'
    )

    with pytest.raises(ValueError, match="duplicate JSON key: decision_id"):
        load_guardrail_decision_json(text)


def test_unknown_top_level_or_claim_fields_are_rejected() -> None:
    payload = _decision().to_mapping()
    with_unknown_top = dict(payload, provider_extension={"ttl": 999})
    with pytest.raises(ValueError, match="unknown fields: provider_extension"):
        guardrail_decision_from_mapping(with_unknown_top)

    claims = dict(payload["claims"])
    claims["mutable_expiry_extension"] = "2026-07-15T13:00:00.000Z"
    with_unknown_claim = dict(payload, claims=claims)
    with pytest.raises(ValueError, match="unknown fields: mutable_expiry_extension"):
        guardrail_decision_from_mapping(with_unknown_claim)


def test_invalid_digest_timestamp_verdict_and_interval_are_rejected() -> None:
    with pytest.raises(ValueError, match="request_digest"):
        _decision(request_digest="not-a-digest")
    with pytest.raises(ValueError, match="verdict"):
        _decision(verdict="MAYBE")
    with pytest.raises(ValueError, match="RFC 3339"):
        _decision(issued_at="2026-07-15T12:00:00Z")
    with pytest.raises(ValueError, match="strictly later"):
        _decision(expires_at="2026-07-15T12:00:00.000Z")


@pytest.mark.parametrize("field_name", ["reason_code", "provider_id"])
@pytest.mark.parametrize("value", ["bad\ud800", "bad\udfff"])
def test_claim_tokens_reject_non_unicode_scalar_values(
    field_name: str, value: str
) -> None:
    with pytest.raises(ValueError, match="Unicode scalar values"):
        _decision(**{field_name: value})


@pytest.mark.parametrize(
    "proof",
    [
        {"bad\ud800": "value"},
        {"value": "bad\udfff"},
        {"nested": ["valid", {"value": "bad\ud800"}]},
    ],
)
def test_proof_rejects_non_unicode_scalar_keys_and_values(proof: object) -> None:
    with pytest.raises(ValueError, match="Unicode scalar values"):
        _decision(proof=proof)


def test_json_loader_rejects_escaped_unpaired_surrogate() -> None:
    payload = _decision().to_mapping()
    payload["claims"]["reason_code"] = "bad\ud800"
    encoded = json.dumps(payload, ensure_ascii=True)

    with pytest.raises(ValueError, match="Unicode scalar values"):
        load_guardrail_decision_json(encoded)


def test_naive_verification_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        verify_guardrail_decision(
            _decision(),
            now=datetime(2026, 7, 15, 12, 1),
        )


@pytest.mark.parametrize(
    "filename",
    [
        "decision-v1-valid.json",
        "decision-v1-expiry-mutated.json",
        "decision-v1-policy-mutated.json",
        "decision-v1-graph-mutated.json",
    ],
)
def test_fixed_vectors_are_independently_recomputable(filename: str) -> None:
    vector = json.loads((VECTORS / filename).read_text(encoding="utf-8"))
    decision = load_guardrail_decision_json(json.dumps(vector["decision"]))
    canonical = canonical_guardrail_decision_json(decision.claims)
    result = verify_guardrail_decision(decision, now=_verification_time())

    assert canonical == vector["canonical_preimage"]
    assert derive_guardrail_decision_id(decision.claims) == vector[
        "recomputed_decision_id"
    ]
    assert [finding.code for finding in result.findings] == vector[
        "expected_finding_codes"
    ]
