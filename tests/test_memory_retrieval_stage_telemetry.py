from __future__ import annotations

import argparse
import importlib
from pathlib import Path
import sys
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".github/trust-root/scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

core = importlib.import_module("memory_retrieval_core")
legacy = importlib.import_module("memory_retrieval_github")
hardened = importlib.import_module("memory_retrieval_hardened")
loop = importlib.import_module("memory_retrieval_hardened_loop")

REPOSITORY = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40
BASE = "b" * 40


class StageApi:
    def __init__(self, fail_at: str) -> None:
        self.fail_at = fail_at

    def pull(self, repository: str, number: int) -> dict[str, Any]:
        if self.fail_at == "pull-api":
            raise core.RetrievalError("sensitive pull detail")
        return {
            "state": "open",
            "title": "workflow fallback",
            "body": "exact base memory retrieval",
            "head": {"sha": HEAD, "ref": "feature/proof"},
            "base": {"sha": BASE, "ref": "main"},
        }

    def files(self, repository: str, number: int) -> list[dict[str, str]]:
        if self.fail_at == "files-api":
            raise core.RetrievalError("sensitive files detail")
        return [{"filename": "docs/proof.md"}]

    def repository(self, repository: str) -> dict[str, str]:
        if self.fail_at == "repository-api":
            raise core.RetrievalError("sensitive repository detail")
        return {"visibility": "public"}

    def comments(self, repository: str, number: int) -> list[dict[str, Any]]:
        return []

    def create_comment(
        self, repository: str, number: int, body: str
    ) -> dict[str, Any]:
        if self.fail_at == "comment-create":
            raise core.RetrievalError("sensitive comment detail")
        return {
            "id": 10,
            "body": body,
            "user": {"login": legacy.BOT_LOGIN},
        }


def invoke(api: StageApi) -> dict[str, Any]:
    return hardened.retrieve_for_pull(
        api=api,
        repository=REPOSITORY,
        pull_number=202,
        run_id=10,
        run_attempt=1,
        run_url="https://example.invalid/run/10",
    )


@pytest.mark.parametrize(
    "stage", ["pull-api", "files-api", "repository-api", "comment-create"]
)
def test_runtime_attaches_allowlisted_failure_stage(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    monkeypatch.setattr(
        legacy,
        "_load_documents",
        lambda *args, **kwargs: ([], 0, 0, []),
    )

    with pytest.raises(core.RetrievalError) as captured:
        invoke(StageApi(stage))

    assert getattr(captured.value, "cml_failure_stage") == stage


def test_corpus_failure_is_staged_without_exposing_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise core.RetrievalError("private/corpus/path.json")

    monkeypatch.setattr(legacy, "_load_documents", fail)

    with pytest.raises(core.RetrievalError) as captured:
        invoke(StageApi("none"))

    assert getattr(captured.value, "cml_failure_stage") == "corpus-load"


def test_failure_artifact_contains_stage_but_not_exception_message() -> None:
    args = argparse.Namespace(
        repository=REPOSITORY,
        run_id="10",
        run_attempt="1",
        run_url="https://example.invalid/run/10",
    )
    exc = core.RetrievalError("private/path.json: secret")
    setattr(exc, "cml_failure_stage", "comment-create")

    result = loop._failure_result(args, exc)

    assert result["failure_stage"] == "comment-create"
    assert result["privacy_summary_redacted"] is True
    assert result["accepted_count"] is None
    assert result["withheld_count"] is None
    assert result["rejected"] == []
    assert "secret" not in str(result)
    assert "private/path" not in str(result)


def test_unknown_stage_is_replaced_with_allowlisted_fallback() -> None:
    args = argparse.Namespace(
        repository=REPOSITORY,
        run_id="10",
        run_attempt="1",
        run_url="https://example.invalid/run/10",
    )
    exc = core.RetrievalError("hidden")
    setattr(exc, "cml_failure_stage", "private/path.json")

    result = loop._failure_result(args, exc, fallback_stage="event-bind")

    assert result["failure_stage"] == "event-bind"
    assert "private/path" not in str(result)
