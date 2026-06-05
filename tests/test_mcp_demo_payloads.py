from scripts.run_mcp_demo_payloads import run_demo


def test_mcp_demo_payload_runner_returns_expected_results():
    result = run_demo()

    assert result["health"]["status"] == "ok"
    assert "audit_trace" in result["health"]["tools"]
    assert "evaluate_cause_band" in result["health"]["tools"]

    audit_result = result["audit_trace"]
    assert audit_result["summary"]["passed"] is False
    assert audit_result["findings"][0]["code"] == "CML-AUDIT-R1-MISSING_PARENT"

    cause_band_result = result["evaluate_cause_band"]
    assert cause_band_result["case_id"] == "mcp-cause-band-degrading-demo"
    assert cause_band_result["trajectory_direction"] == "degrading"
    assert cause_band_result["recovered_to_safe"] is False
    assert cause_band_result["oscillating"] is False
    assert cause_band_result["predicted_codes"] == [
        "CML-AUDIT-RANGE-CRITICAL_EXIT",
        "CML-AUDIT-RANGE-DRIFT",
        "CML-AUDIT-RANGE-PERSISTENT_DEVIATION",
    ]
