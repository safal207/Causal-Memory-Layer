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
SOURCE = "c" * 40


def memory() -> core.MemoryDocument:
    return core.MemoryDocument(
        path=f"{core.MEMORY_ROOT}/public.json",
        pack_id="d" * 64,
        source_commit=SOURCE,
        visibility="public",
        contains_private_data=False,
        situation="GitHub workflow pull request creation was blocked",
        selected_path=(
            "GitHub workflow pull request creation was blocked",
            "Use an exact generated branch and review fallback",
            "CI and security validation passed",
        ),
        constraints=("No direct main write or merge authority",),
        token_weights={
            "github": 4,
            "workflow": 5,
            "pull": 2,
            "fallback": 5,
        },
        evidence_count=2,
    )


class FakeApi:
    def __init__(
        self,
        *,
        visibility: str = "public",
        comments: list[dict[str, Any]] | None = None,
        race_on_create: bool = False,
        fail_delete: bool = False,
    ) -> None:
        self.visibility = visibility
        self.comment_items = list(comments or [])
        self.race_on_create = race_on_create
        self.fail_delete = fail_delete
        self.created: list[str] = []
        self.updated: list[tuple[int, str]] = []
        self.deleted: list[int] = []

    def pull(self, repository: str, number: int) -> dict[str, Any]:
        return {
            "number": number,
            "state": "open",
            "title": "Harden GitHub workflow pull request fallback",
            "body": "Use an exact generated branch and deterministic memory ranking.",
            "head": {"sha": HEAD, "ref": "feature/hardening"},
            "base": {"sha": BASE, "ref": "main"},
        }

    def files(self, repository: str, number: int) -> list[dict[str, Any]]:
        return [{"filename": ".github/workflows/example.yml"}]

    def repository(self, repository: str) -> dict[str, Any]:
        return {"visibility": self.visibility}

    def comments(self, repository: str, number: int) -> list[dict[str, Any]]:
        return [dict(item) for item in self.comment_items]

    def create_comment(
        self, repository: str, number: int, body: str
    ) -> dict[str, Any]:
        self.created.append(body)
        if self.race_on_create:
            self.comment_items.append(
                {
                    "id": 50,
                    "body": core.COMMENT_MARKER + " competing run",
                    "user": {"login": legacy.BOT_LOGIN},
                }
            )
        comment = {
            "id": 100,
            "body": body,
            "user": {"login": legacy.BOT_LOGIN},
        }
        self.comment_items.append(comment)
        return dict(comment)

    def update_comment(
        self, repository: str, comment_id: int, body: str
    ) -> dict[str, Any]:
        self.updated.append((comment_id, body))
        for item in self.comment_items:
            if item.get("id") == comment_id:
                item["body"] = body
        return {"id": comment_id, "body": body}

    def delete_comment(self, repository: str, comment_id: int) -> None:
        if self.fail_delete:
            raise core.RetrievalError("delete blocked")
        self.deleted.append(comment_id)
        self.comment_items = [
            item for item in self.comment_items if item.get("id") != comment_id
        ]


def install_documents(
    monkeypatch: pytest.MonkeyPatch,
    *,
    accepted_count: int = 3,
    withheld_count: int = 2,
    rejected: list[str] | None = None,
) -> None:
    def load_documents(*args: Any, **kwargs: Any) -> tuple[Any, int, int, list[str]]:
        return (
            [memory()],
            accepted_count,
            withheld_count,
            list(rejected or ["private/invalid.json: hidden detail"]),
        )

    monkeypatch.setattr(legacy, "_load_documents", load_documents)


def run(api: FakeApi) -> dict[str, Any]:
    return hardened.retrieve_for_pull(
        api=api,
        repository=REPOSITORY,
        pull_number=42,
        run_id=10,
        run_attempt=1,
        run_url="https://example.invalid/run/10",
    )


def bot_comments(api: FakeApi) -> list[dict[str, Any]]:
    return [
        item
        for item in api.comment_items
        if item.get("user", {}).get("login") == legacy.BOT_LOGIN
        and core.COMMENT_MARKER in item.get("body", "")
    ]


def test_public_comment_and_artifact_hide_private_corpus_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_documents(monkeypatch)
    api = FakeApi(visibility="public")

    result = run(api)
    body = api.created[0]

    assert "Accepted candidates:" not in body
    assert "withheld by privacy" not in body
    assert "rejected as invalid" not in body
    assert "hidden detail" not in body
    assert "Publishable candidates evaluated: **1**" in body
    assert result["accepted_count"] is None
    assert result["withheld_count"] is None
    assert result["rejected_count"] is None
    assert result["rejected"] == []
    assert result["publishable_count"] == 1
    assert result["privacy_summary_redacted"] is True


def test_private_repository_retains_repository_local_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_documents(monkeypatch)
    api = FakeApi(visibility="private")

    result = run(api)
    body = api.created[0]

    assert "Accepted candidates: **3**" in body
    assert "withheld by privacy: **2**" in body
    assert "rejected as invalid: **1**" in body
    assert result["accepted_count"] == 3
    assert result["withheld_count"] == 2
    assert result["rejected_count"] == 1
    assert result["privacy_summary_redacted"] is False


def test_existing_duplicate_bot_comments_are_deleted_but_human_spoof_survives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_documents(monkeypatch)
    api = FakeApi(
        comments=[
            {
                "id": 5,
                "body": core.COMMENT_MARKER + " human spoof",
                "user": {"login": "human"},
            },
            {
                "id": 10,
                "body": core.COMMENT_MARKER + " old canonical",
                "user": {"login": legacy.BOT_LOGIN},
            },
            {
                "id": 20,
                "body": core.COMMENT_MARKER + " stale duplicate",
                "user": {"login": legacy.BOT_LOGIN},
            },
        ]
    )

    result = run(api)

    assert result["comment_action"] == "updated"
    assert result["comment_id"] == 10
    assert result["duplicate_managed_comments"] == 1
    assert api.deleted == [20]
    assert len(bot_comments(api)) == 1
    assert any(item.get("id") == 5 for item in api.comment_items)


def test_create_race_reconciles_to_oldest_comment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_documents(monkeypatch)
    api = FakeApi(race_on_create=True)

    result = run(api)

    assert result["comment_action"] == "created-and-reconciled"
    assert result["comment_id"] == 50
    assert result["duplicate_managed_comments"] == 1
    assert api.deleted == [100]
    assert len(bot_comments(api)) == 1
    assert bot_comments(api)[0]["id"] == 50


def test_duplicate_delete_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_documents(monkeypatch)
    api = FakeApi(
        comments=[
            {
                "id": 10,
                "body": core.COMMENT_MARKER + " canonical",
                "user": {"login": legacy.BOT_LOGIN},
            },
            {
                "id": 20,
                "body": core.COMMENT_MARKER + " duplicate",
                "user": {"login": legacy.BOT_LOGIN},
            },
        ],
        fail_delete=True,
    )

    with pytest.raises(core.RetrievalError, match="delete blocked"):
        run(api)


def test_failure_artifact_is_generic_and_privacy_redacted() -> None:
    args = argparse.Namespace(
        repository=REPOSITORY,
        run_id="10",
        run_attempt="1",
        run_url="https://example.invalid/run/10",
    )

    result = loop._failure_result(
        args, core.RetrievalError("private/path.json: sensitive value")
    )

    assert result["accepted_count"] is None
    assert result["withheld_count"] is None
    assert result["rejected_count"] is None
    assert result["rejected"] == []
    assert result["privacy_summary_redacted"] is True
    assert result["error"]["message"] == "CML retrieval failed closed"
    assert "sensitive" not in str(result)
