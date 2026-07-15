from __future__ import annotations

import cml.integrations as integrations


def test_guardrail_decision_public_api_is_exported() -> None:
    expected = {
        "GUARDRAIL_DECISION_SCHEMA",
        "GuardrailDecisionClaimsV1",
        "GuardrailDecisionFinding",
        "GuardrailDecisionV1",
        "GuardrailDecisionVerificationResult",
        "canonical_guardrail_decision_json",
        "derive_guardrail_decision_id",
        "guardrail_decision_from_mapping",
        "issue_guardrail_decision",
        "load_guardrail_decision_json",
        "verify_guardrail_decision",
    }

    assert expected == set(integrations.__all__)
    for name in expected:
        assert getattr(integrations, name) is not None
