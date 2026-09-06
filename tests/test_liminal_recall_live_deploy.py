from __future__ import annotations

import importlib.util
import re
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


def test_runtime_proof_uses_distinct_semantic_inputs() -> None:
    outcome, decision = MODULE._runtime_proof_payloads()

    outcome_tokens = set(re.findall(r"[a-z0-9-]+", outcome["content"].casefold()))
    outcome_tokens.update(tag.casefold() for tag in outcome["tags"])
    decision_tokens = set(
        re.findall(r"[a-z0-9-]+", decision["proposed_action"].casefold())
    )
    decision_tokens.update(tag.casefold() for tag in decision["tags"])

    assert outcome["session_id"] == decision["session_id"]
    assert outcome["content"] != decision["proposed_action"]
    assert outcome["tags"] != decision["tags"]
    assert outcome_tokens.isdisjoint(decision_tokens)
    assert outcome["status"] == "negative"


def test_runtime_build_must_match_reviewed_head() -> None:
    expected = "a" * 40

    assert MODULE._verify_runtime_build(
        {"build_sha": expected},
        expected,
        stage="pre-restart",
    ) == expected

    with pytest.raises(MODULE.DeploymentError, match="does not match"):
        MODULE._verify_runtime_build(
            {"build_sha": "b" * 40},
            expected,
            stage="pre-restart",
        )


def test_capture_rejects_expected_sha_detached_from_clean_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clean_head = "b" * 40
    stale_head = "a" * 40
    capture_calls: list[tuple[str, str, str]] = []
    monkeypatch.setattr(MODULE, "_require_clean_repository", lambda: clean_head)
    monkeypatch.setattr(
        MODULE,
        "capture_runtime_proof",
        lambda url, name, sha: capture_calls.append((url, name, sha)),
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        [
            str(SCRIPT_PATH),
            "capture",
            "--function-url",
            "https://example.invalid",
            "--function-name",
            "liminal-recall",
            "--expected-build-sha",
            stale_head,
        ],
    )

    assert MODULE.main() == 1
    assert capture_calls == []


def test_capture_uses_clean_head_as_authoritative_build_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clean_head = "c" * 40
    capture_calls: list[tuple[str, str, str]] = []
    monkeypatch.setattr(MODULE, "_require_clean_repository", lambda: clean_head)
    monkeypatch.setattr(
        MODULE,
        "capture_runtime_proof",
        lambda url, name, sha: capture_calls.append((url, name, sha)),
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        [
            str(SCRIPT_PATH),
            "capture",
            "--function-url",
            "https://example.invalid/",
            "--function-name",
            "liminal-recall",
            "--expected-build-sha",
            clean_head,
        ],
    )

    assert MODULE.main() == 0
    assert capture_calls == [
        ("https://example.invalid", "liminal-recall", clean_head)
    ]


def test_required_environment_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in MODULE.REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(MODULE.DeploymentError, match="missing required environment"):
        MODULE._required_environment()


def test_required_environment_includes_demo_key(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in MODULE.REQUIRED_ENV:
        monkeypatch.setenv(name, "synthetic-value")
    monkeypatch.delenv("DEMO_API_KEY")

    with pytest.raises(MODULE.DeploymentError, match="DEMO_API_KEY"):
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
