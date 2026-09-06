"""Regression tests for Qwen, Kimi, and DeepSeek provider envelopes."""

import pytest

from examples.grok_xai_causal_audit import audit_trace
from examples.qwen_kimi_deepseek_causal_audit import make_provider_trace

PROVIDERS = ("qwen", "kimi", "deepseek")


def _tool_records(records):
    return [
        record
        for record in records
        if isinstance(record.object, dict) and "tool" in record.object
    ]


@pytest.mark.parametrize("provider", PROVIDERS)
def test_invalid_trace_preserves_core_cml_findings(provider):
    result = audit_trace(make_provider_trace(provider, valid=False))
    codes = {finding.code for finding in result.findings}

    assert not result.passed()
    assert "CML-AUDIT-R1-MISSING_PARENT" in codes
    assert "CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL" in codes


@pytest.mark.parametrize("provider", PROVIDERS)
def test_valid_trace_passes_core_cml_audit(provider):
    result = audit_trace(make_provider_trace(provider, valid=True))

    assert result.passed()
    assert result.findings == []


@pytest.mark.parametrize("provider", PROVIDERS)
def test_tool_result_uses_exact_tool_call_id(provider):
    for record in _tool_records(make_provider_trace(provider, valid=True)):
        envelope = record.object["provider_envelope"]
        call = envelope["assistant_message"]["tool_call"]
        result = envelope["tool_message"]

        assert envelope["provider"] == provider
        assert call["type"] == "function"
        assert result["role"] == "tool"
        assert call["id"] == result["tool_call_id"]
        assert call["function"]["name"] == record.object["tool"]


def test_kimi_reasoning_content_is_replayed_but_not_stored_raw():
    for record in _tool_records(make_provider_trace("kimi", valid=True)):
        handling = record.object["provider_envelope"][
            "reasoning_content_handling"
        ]

        assert handling["required_in_thinking_mode"] is True
        assert handling["replayed_to_provider"] is True
        assert handling["stored_raw_in_cml"] is False
        assert handling["digest"].startswith("sha256:")
        assert handling["allowed_tool_choice"] == ["auto", "none"]


def test_qwen_keeps_host_side_pre_tool_gate_visible():
    for record in _tool_records(make_provider_trace("qwen", valid=True)):
        envelope = record.object["provider_envelope"]

        assert envelope["execution_boundary"] == "host_custom_function"
        assert (
            envelope["thinking_mode"]
            == "disabled_for_deterministic_pre_tool_gate"
        )


def test_deepseek_records_beta_strict_mode_without_claiming_enforcement():
    for record in _tool_records(make_provider_trace("deepseek", valid=True)):
        envelope = record.object["provider_envelope"]

        assert envelope["strict_mode"] == "beta_available"
        assert envelope["execution_boundary"] == "host_custom_function"
