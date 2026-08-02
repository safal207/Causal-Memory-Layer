from __future__ import annotations

import importlib.util
import signal
import subprocess
from pathlib import Path

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "hackathons"
    / "liminal-recall"
    / "scripts"
    / "live_deploy.py"
)
SPEC = importlib.util.spec_from_file_location("liminal_recall_live_deploy", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def valid_decision(outcome_id: str = "outcome-1") -> dict:
    return {
        "decision": "HUMAN_REVIEW",
        "memory_ids": [outcome_id],
        "retrieval": {
            "mode": "cockroachdb_vector_cosine",
            "tool": "distributed_vector_index",
        },
        "execution": {
            "status": "NOT_EXECUTED",
            "authority": "advisory_only",
        },
    }


def test_verify_decision_accepts_complete_live_proof() -> None:
    MODULE._verify_decision(valid_decision(), "outcome-1")


def test_verify_decision_rejects_overclaimed_execution() -> None:
    decision = valid_decision()
    decision["execution"]["status"] = "EXECUTED"

    with pytest.raises(MODULE.DeploymentError, match="NOT_EXECUTED"):
        MODULE._verify_decision(decision, "outcome-1")


def test_verify_decision_requires_exact_memory_uuid() -> None:
    with pytest.raises(MODULE.DeploymentError, match="outcome UUID"):
        MODULE._verify_decision(valid_decision("different-memory"), "outcome-1")


def test_runtime_proof_uses_identical_embedding_input() -> None:
    outcome, decision = MODULE._runtime_proof_payloads()

    assert outcome["session_id"] == decision["session_id"]
    assert outcome["content"] == decision["proposed_action"]
    assert outcome["tags"] == decision["tags"]
    assert outcome["status"] == "negative"


def test_required_environment_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in MODULE.REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(MODULE.DeploymentError, match="missing required environment"):
        MODULE._required_environment()



def test_run_reports_signal_and_redacted_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_secret = "synthetic-database-secret"
    api_key = "synthetic-api-key-secret"
    account_id = "123456" + "789012"
    endpoint = "https:" + "//service.invalid/private"
    monkeypatch.setenv("DATABASE_URL", database_secret)
    stdout = "\n".join(
        ["early stdout that should be truncated"]
        + [f"Uploading artifact {index}.00%" for index in range(20)]
        + ["final useful stdout line"]
    )
    stderr = (
        f"endpoint={endpoint}; account={account_id}; "
        f"api_key={api_key}; database={database_secret}"
    )

    def fail_run(*args: object, **kwargs: object) -> None:
        raise subprocess.CalledProcessError(
            -signal.SIGKILL,
            ["sam", "deploy"],
            output=stdout,
            stderr=stderr,
        )

    monkeypatch.setattr(MODULE.subprocess, "run", fail_run)

    with pytest.raises(MODULE.DeploymentError) as exc_info:
        MODULE._run(
            ["sam", "deploy", "--parameter-overrides", database_secret],
            label="deploy Lambda and Bedrock integration",
        )

    message = str(exc_info.value)
    assert "command stage: deploy Lambda and Bedrock integration" in message
    assert f"return code: {-signal.SIGKILL}" in message
    assert "signal: SIGKILL" in message
    assert "stderr:" in message
    assert "final stdout:" in message
    assert "final useful stdout line" in message
    assert "early stdout that should be truncated" not in message
    assert database_secret not in message
    assert api_key not in message
    assert account_id not in message
    assert endpoint not in message


def test_run_reports_timeout_duration_and_partial_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = "https:" + "//service.invalid/private"

    def time_out(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(
            ["sam", "deploy"],
            31.5,
            output=b"final partial stdout",
            stderr=f"network timeout at {endpoint}".encode(),
        )

    monkeypatch.setattr(MODULE.subprocess, "run", time_out)

    with pytest.raises(MODULE.DeploymentError) as exc_info:
        MODULE._run(
            ["sam", "deploy"],
            label="deploy Lambda and Bedrock integration",
            timeout=31.5,
        )

    message = str(exc_info.value)
    assert "command stage: deploy Lambda and Bedrock integration" in message
    assert "return code: unavailable" in message
    assert "timeout: 31.5 seconds" in message
    assert "network timeout at [REDACTED_URL]" in message
    assert "final partial stdout" in message
    assert endpoint not in message
