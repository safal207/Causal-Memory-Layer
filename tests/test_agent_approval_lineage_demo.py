"""Regression tests for the agent approval-lineage audit demo."""

from cml.audit import AuditConfig, AuditEngine

from examples.agent_approval_lineage_audit import (
    APPROVAL_LINEAGE_RULES,
    make_invalid_trace,
    make_valid_trace,
)


def _codes_for(records):
    config = AuditConfig.from_yaml_string(APPROVAL_LINEAGE_RULES)
    result = AuditEngine(config).run(records)
    return result, {finding.code for finding in result.findings}


def test_invalid_trace_flags_missing_policy_and_human_approval():
    result, codes = _codes_for(make_invalid_trace())

    assert not result.passed()
    assert "CML-AUDIT-R7-ML_ACTION_REQUIRES_POLICY_APPROVAL" in codes
    assert "CML-AUDIT-R5-EXEC_REQUIRES_HUMAN_APPROVAL" in codes


def test_valid_trace_passes_approval_lineage_rules():
    result, codes = _codes_for(make_valid_trace())

    assert result.passed()
    assert "CML-AUDIT-R7-ML_ACTION_REQUIRES_POLICY_APPROVAL" not in codes
    assert "CML-AUDIT-R5-EXEC_REQUIRES_HUMAN_APPROVAL" not in codes
