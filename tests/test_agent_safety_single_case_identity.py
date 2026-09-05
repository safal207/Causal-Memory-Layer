from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = "benchmarks/agent_safety/reference_submission.json"


def run_single_case_with_agent(agent: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "scripts/run_agent_safety_benchmark.py",
            "--case",
            "ASB-01",
            "--submission",
            REFERENCE,
            "--agent",
            agent,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_full_submission_preserves_validated_agent_identity() -> None:
    completed = run_single_case_with_agent("cml-reference-policy-v0.1")
    assert completed.returncode == 0, completed.stderr
    assert "agent=cml-reference-policy-v0.1" in completed.stdout
    assert "passed=1/1" in completed.stdout


def test_full_submission_rejects_agent_identity_override() -> None:
    completed = run_single_case_with_agent("renamed-reference-policy")
    assert completed.returncode != 0
    assert "agent override does not match submission.agent" in completed.stderr
