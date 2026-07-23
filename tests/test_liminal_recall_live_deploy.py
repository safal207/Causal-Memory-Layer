from __future__ import annotations

import importlib.util
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


def test_required_environment_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in MODULE.REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(MODULE.DeploymentError, match="missing required environment"):
        MODULE._required_environment()
