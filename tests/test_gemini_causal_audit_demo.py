"""Regression tests for the Gemini function-calling causal-audit demo."""

from examples.gemini_causal_audit import make_gemini_trace
from examples.grok_xai_causal_audit import audit_trace


def _tool_records(records):
    return [
        record
        for record in records
        if isinstance(record.object, dict) and "tool" in record.object
    ]


def test_invalid_gemini_trace_preserves_core_cml_findings():
    result = audit_trace(make_gemini_trace(valid=False))
    codes = {finding.code for finding in result.findings}

    assert not result.passed()
    assert "CML-AUDIT-R1-MISSING_PARENT" in codes
    assert "CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL" in codes


def test_valid_gemini_trace_passes_core_cml_audit():
    result = audit_trace(make_gemini_trace(valid=True))

    assert result.passed()
    assert result.findings == []


def test_function_response_uses_exact_function_call_id():
    for record in _tool_records(make_gemini_trace(valid=True)):
        envelope = record.object["provider_envelope"]
        call = envelope["model_part"]
        response = envelope["user_part"]

        assert envelope["provider"] == "gemini"
        assert call["sdk_type"] == "function_call"
        assert call["wire_key"] == "functionCall"
        assert response["sdk_type"] == "function_response"
        assert response["wire_key"] == "functionResponse"
        assert call["id"] == response["id"]
        assert call["name"] == response["name"]


def test_thought_signature_is_preserved_opaquely_not_stored_raw():
    for record in _tool_records(make_gemini_trace(valid=True)):
        signature = record.object["provider_envelope"]["model_part"][
            "thought_signature"
        ]

        assert signature["present"] is True
        assert signature["preserved_opaque"] is True
        assert signature["stored_raw"] is False
        assert signature["digest"].startswith("sha256:")


def test_manual_execution_boundary_keeps_pre_tool_gate_visible():
    for record in _tool_records(make_gemini_trace(valid=True)):
        envelope = record.object["provider_envelope"]

        assert envelope["execution_boundary"] == "host_custom_function"
        assert (
            envelope["automatic_function_calling"]
            == "disabled_for_pre_tool_gate"
        )
