import subprocess
import sys


def test_mcp_demo_payload_runner_command_returns_expected_results():
    completed = subprocess.run(
        [sys.executable, "scripts/run_mcp_demo_payloads.py"],
        check=True,
        capture_output=True,
        text=True,
    )

    output = completed.stdout

    assert "## health" in output
    assert '"status": "ok"' in output
    assert '"audit_trace"' in output
    assert '"evaluate_cause_band"' in output

    assert "## audit_trace" in output
    assert '"passed": false' in output
    assert "CML-AUDIT-R1-MISSING_PARENT" in output

    assert "## evaluate_cause_band" in output
    assert '"case_id": "mcp-cause-band-degrading-demo"' in output
    assert '"trajectory_direction": "degrading"' in output
    assert '"recovered_to_safe": false' in output
    assert '"oscillating": false' in output
    assert "CML-AUDIT-RANGE-CRITICAL_EXIT" in output
    assert "CML-AUDIT-RANGE-DRIFT" in output
    assert "CML-AUDIT-RANGE-PERSISTENT_DEVIATION" in output
