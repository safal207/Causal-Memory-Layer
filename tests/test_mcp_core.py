from cml.integrations.mcp.core import audit_trace, evaluate_cause_band, health


def test_mcp_core_health_lists_available_tools():
    result = health()

    assert result["service"] == "cml-agent-audit-mcp"
    assert result["status"] == "ok"
    assert "audit_trace" in result["tools"]
    assert "evaluate_cause_band" in result["tools"]


def test_mcp_core_audit_trace_accepts_records_payload():
    payload = {
        "records": [
            {
                "id": "root",
                "timestamp": 1,
                "actor": {"pid": 100, "uid": 1000},
                "action": "exec",
                "object": "/bin/app",
                "permitted_by": "root_event:user_request",
                "parent_cause": None,
            },
            {
                "id": "child",
                "timestamp": 2,
                "actor": {"pid": 100, "uid": 1000},
                "action": "open",
                "object": "/tmp/readme.txt",
                "permitted_by": "fs:read",
                "parent_cause": "missing-parent",
            },
        ]
    }

    result = audit_trace(payload)

    assert result["summary"]["passed"] is False
    assert result["findings"][0]["code"] == "CML-AUDIT-R1-MISSING_PARENT"


def test_mcp_core_evaluate_cause_band_accepts_sidecar_payload():
    payload = {
        "cause_band_sidecar": {
            "case_id": "mcp-sidecar-test",
            "status": "experimental",
            "cause_band_policy": {"duration_threshold": "3_steps"},
            "trajectory": [
                {"step": 1, "band": "safe_range"},
                {"step": 2, "band": "warning_range"},
                {"step": 3, "band": "danger_range"},
                {"step": 4, "band": "critical_range"},
            ],
            "expected_future_cause_band_behavior": {
                "expected_codes": [
                    "CML-AUDIT-RANGE-DRIFT",
                    "CML-AUDIT-RANGE-PERSISTENT_DEVIATION",
                    "CML-AUDIT-RANGE-CRITICAL_EXIT",
                ]
            },
        }
    }

    result = evaluate_cause_band(payload)

    assert result["case_id"] == "mcp-sidecar-test"
    assert result["trajectory_direction"] == "degrading"
    assert result["recovered_to_safe"] is False
    assert result["oscillating"] is False
    assert result["matches_expected_future"] is True
