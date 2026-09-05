"""Regression tests for the Grok/xAI-style LLM tool-use audit demo."""

from examples.grok_xai_causal_audit import (
    INVALID_CAUSE_BAND,
    VALID_CAUSE_BAND,
    audit_trace,
    make_invalid_trace,
    make_valid_trace,
)
from cml.experimental.cause_band import evaluate_fixture


def test_invalid_trace_flags_missing_parent_and_missing_human_approval():
    result = audit_trace(make_invalid_trace())
    codes = {finding.code for finding in result.findings}

    assert not result.passed()
    assert "CML-AUDIT-R1-MISSING_PARENT" in codes
    assert "CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL" in codes


def test_valid_trace_passes_core_audit():
    result = audit_trace(make_valid_trace())

    assert result.passed()
    assert result.findings == []


def test_every_simulated_tool_call_contains_llm_native_audit_metadata():
    required = {
        "intent_description",
        "risk_level",
        "human_approval",
        "evidence_bundle",
    }

    for record in make_valid_trace():
        if not isinstance(record.object, dict) or "tool" not in record.object:
            continue
        assert required.issubset(record.object)


def test_cause_band_distinguishes_drift_from_in_band_execution():
    invalid = evaluate_fixture(INVALID_CAUSE_BAND)
    valid = evaluate_fixture(VALID_CAUSE_BAND)

    assert "CML-AUDIT-RANGE-DRIFT" in invalid["predicted_codes"]
    assert "CML-AUDIT-RANGE-CRITICAL_EXIT" in invalid["predicted_codes"]
    assert valid["predicted_codes"] == []
