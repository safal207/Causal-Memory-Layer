"""Regression tests for OpenAI and Claude provider envelope mappings."""

import pytest

from examples.openai_claude_causal_audit import make_provider_trace
from examples.grok_xai_causal_audit import audit_trace


@pytest.mark.parametrize("provider", ["openai", "claude"])
def test_invalid_provider_trace_preserves_core_cml_findings(provider):
    result = audit_trace(make_provider_trace(provider, valid=False))
    codes = {finding.code for finding in result.findings}

    assert not result.passed()
    assert "CML-AUDIT-R1-MISSING_PARENT" in codes
    assert "CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL" in codes


@pytest.mark.parametrize("provider", ["openai", "claude"])
def test_valid_provider_trace_passes_core_cml_audit(provider):
    result = audit_trace(make_provider_trace(provider, valid=True))

    assert result.passed()
    assert result.findings == []


def test_openai_function_call_output_uses_same_call_id():
    records = make_provider_trace("openai", valid=True)

    for record in records:
        if not isinstance(record.object, dict) or "tool" not in record.object:
            continue
        envelope = record.object["provider_envelope"]
        assert envelope["provider"] == "openai"
        assert envelope["request_item"]["type"] == "function_call"
        assert envelope["result_item"]["type"] == "function_call_output"
        assert (
            envelope["request_item"]["call_id"]
            == envelope["result_item"]["call_id"]
        )


def test_claude_tool_result_points_to_tool_use_block():
    records = make_provider_trace("claude", valid=True)

    for record in records:
        if not isinstance(record.object, dict) or "tool" not in record.object:
            continue
        envelope = record.object["provider_envelope"]
        assert envelope["provider"] == "claude"
        assert envelope["assistant_stop_reason"] == "tool_use"
        assert envelope["request_block"]["type"] == "tool_use"
        assert envelope["result_block"]["type"] == "tool_result"
        assert (
            envelope["request_block"]["id"]
            == envelope["result_block"]["tool_use_id"]
        )
