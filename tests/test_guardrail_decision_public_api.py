from __future__ import annotations

import cml.integrations as integrations


def test_integrations_public_api_is_exported() -> None:
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
        "MEMORY_PACK_SCHEMA",
        "MemoryEdgeV1",
        "MemoryEvidenceV1",
        "MemoryGraphV1",
        "MemoryNodeV1",
        "MemoryPackFinding",
        "MemoryPackManifestV1",
        "MemoryPackV1",
        "MemoryPackVerificationResult",
        "MemoryRedactionV1",
        "canonical_memory_pack_json",
        "derive_memory_pack_id",
        "issue_memory_pack",
        "load_memory_pack_json",
        "memory_pack_from_mapping",
        "verify_memory_pack",
    }

    assert expected == set(integrations.__all__)
    for name in expected:
        assert getattr(integrations, name) is not None
