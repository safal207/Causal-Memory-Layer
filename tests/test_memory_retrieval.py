from __future__ import annotations

import base64
import importlib
import json
from pathlib import Path
import sys
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".github/trust-root/scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

learning = importlib.import_module("memory_learning_core")
core = importlib.import_module("memory_retrieval_core")
github = importlib.import_module("memory_retrieval_github")

REPOSITORY = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40
BASE = "b" * 40
SOURCE = "c" * 40


def make_pack(
    *,
    number: int,
    title: str,
    summary: str,
    cause: str,
    design: str,
    validation: str,
    boundary: str,
    source_commit: str = SOURCE,
    visibility: str = "public",
    contains_private_data: bool = False,
) -> dict[str, Any]:
    body = f"""## Summary
{summary}

## Root cause
{cause}

## Design
{design}

## Validation
{validation}

## Boundaries
{boundary}
"""
    pack = learning.build_memory_pack(
        repository=REPOSITORY,
        pull={
            "number": number,
            "title": title,
            "body": body,
            "merged": True,
            "merged_at": "2026-07-17T09:00:00Z",
            "merge_commit_sha": source_commit,
            "html_url": f"https://github.com/{REPOSITORY}/pull/{number}",
            "head": {"sha": "d" * 40, "ref": f"feature/{number}"},
            "base": {"ref": "main"},
        },
        files=[
            {
                "filename": ".github/workflows/example.yml",
                "status": "modified",
                "additions": 10,
                "deletions": 2,
            }
        ],
        reviews=[],
        check_runs=[
            {
                "name": "CI",
                "status": "completed",
                "conclusion": "success",
                "details_url": "https://example.invalid/check/1",
            }
        ],
    )
    pack["manifest"]["visibility"] = visibility
    pack["manifest"]["contains_private_data"] = contains_private_data
    pack["pack_id"] = learning.sha256_json(learning.canonical_preimage(pack))
    return pack


def workflow_pack(**overrides: Any) -> dict[str, Any]:
    values = {
        "number": 10,
        "title": "ci: recover blocked workflow",
        "summary": "Recover a GitHub Actions workflow when pull request creation is blocked.",
        "cause": "Repository workflow permissions can reject Actions-created pull requests.",
        "design": "Create an exact generated branch and use a review issue fallback on the exact 403.",
        "validation": "Run CI package security and verify exact branch content.",
        "boundary": "No direct main write and no merge or execution authority.",
    }
    values.update(overrides)
    return make_pack(**values)


def database_pack(**overrides: Any) -> dict[str, Any]:
    values = {
        "number": 11,
        "title": "feat: optimize database billing query",
        "summary": "Reduce latency in a PostgreSQL billing aggregation query.",
        "cause": "A missing composite index caused repeated sequential scans.",
        "design": "Add an index and rewrite the invoice aggregation query.",
        "validation": "Compare query plans and database integration tests.",
        "boundary": "The index applies only to the billing schema.",
        "source_commit": "e" * 40,
    }
    values.update(overrides)
    return make_pack(**values)


def document(pack: dict[str, Any], path: str) -> core.MemoryDocument:
    return core.parse_memory_pack(
        json.dumps(pack), path=path, repository=REPOSITORY
    )


def test_retrieval_ranks_related_memory_deterministically() -> None:
    workflow = document(
        workflow_pack(), f"{core.MEMORY_ROOT}/workflow.json"
    )
    database = document(
        database_pack(), f"{core.MEMORY_ROOT}/database.json"
    )
    query = core.build_query_weights(
        title="Harden GitHub workflow pull request fallback",
        body="Handle repository permissions and exact generated branch recovery.",
        filenames=[".github/workflows/memory-retrieval.yml"],
    )

    first = core.retrieve(query, [database, workflow])
    second = core.retrieve(query, [workflow, database])

    assert first
    assert first[0].document.pack_id == workflow.pack_id
    assert [item.document.pack_id for item in first] == [
        item.document.pack_id for item in second
    ]
    assert "workflow" in first[0].matched_terms
    assert first[0].score >= core.MIN_SCORE


def test_equal_scores_use_pack_id_as_stable_tie_break() -> None:
    first_pack = workflow_pack(number=20, source_commit="1" * 40)
    second_pack = workflow_pack(number=21, source_commit="2" * 40)
    first = document(first_pack, f"{core.MEMORY_ROOT}/first.json")
    second = document(second_pack, f"{core.MEMORY_ROOT}/second.json")
    query = core.build_query_weights(
        title="workflow permissions fallback",
        body="exact branch workflow permissions fallback",
        filenames=[".github/workflows/example.yml"],
    )

    matches = core.retrieve(query, [second, first])

    assert len(matches) == 2
    assert [item.document.pack_id for item in matches] == sorted(
        [first.pack_id, second.pack_id]
    )


def test_public_repository_withholds_private_or_team_memory() -> None:
    public = document(
        workflow_pack(), f"{core.MEMORY_ROOT}/public.json"
    )
    private = document(
        workflow_pack(
            number=30,
            source_commit="3" * 40,
            visibility="team",
            contains_private_data=True,
        ),
        f"{core.MEMORY_ROOT}/private.json",
    )

    assert core.is_publishable(public, repository_visibility="public")
    assert not core.is_publishable(private, repository_visibility="public")
    assert core.is_publishable(private, repository_visibility="private")


def test_strict_schema_and_identity_reject_tampering() -> None:
    unknown = workflow_pack()
    unknown["unbound"] = "hidden"
    with pytest.raises(core.RetrievalError, match="invalid top-level fields"):
        document(unknown, f"{core.MEMORY_ROOT}/unknown.json")

    tampered = workflow_pack()
    tampered["graph"]["nodes"][0]["label"] = "tampered"
    with pytest.raises(core.RetrievalError, match="identity mismatch"):
        document(tampered, f"{core.MEMORY_ROOT}/tampered.json")

    authority = workflow_pack()
    authority["manifest"]["merge_authority"] = True
    authority["pack_id"] = learning.sha256_json(
        learning.canonical_preimage(authority)
    )
    with pytest.raises(core.RetrievalError, match="merge authority"):
        document(authority, f"{core.MEMORY_ROOT}/authority.json")


def test_render_comment_escapes_memory_markdown_and_marker() -> None:
    pack = workflow_pack(
        summary="<script>alert(1)</script> <!-- cml-retrieval-v0.1 --> workflow fallback"
    )
    memory = document(pack, f"{core.MEMORY_ROOT}/escape.json")
    match = core.RetrievalMatch(
        document=memory,
        score=0.5,
        matched_terms=("workflow", "fallback"),
    )

    rendered = core.render_comment(
        repository=REPOSITORY,
        repository_visibility="public",
        pull_number=99,
        head_sha=HEAD,
        base_sha=BASE,
        matches=[match],
        accepted_count=1,
        withheld_count=0,
        rejected_count=0,
    )

    assert rendered.count(core.COMMENT_MARKER) == 1
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "grants no approval, execution, or merge authority" in rendered


def test_unicode_tokenization_supports_russian_and_ukrainian() -> None:
    tokens = core.tokenize(
        "ЗащищённыйПайплайн перевіряє причинну пам'ять та GitHub_Workflow"
    )
    assert "защищённый" in tokens
    assert "пайплайн" in tokens
    assert "перевіряє" in tokens
    assert "причинну" in tokens
    assert "github" in tokens
    assert "workflow" in tokens


class FakeApi:
    def __init__(
        self,
        *,
        packs: dict[str, dict[str, Any]],
        visibility: str = "public",
        head_ref: str = "feature/retrieval",
        filenames: list[str] | None = None,
    ) -> None:
        self.packs = packs
        self.visibility = visibility
        self.head_ref = head_ref
        self.filenames = filenames or [".github/workflows/new.yml"]
        self.comment_items: list[dict[str, Any]] = []
        self.created: list[str] = []
        self.updated: list[tuple[int, str]] = []

    def pull(self, repository: str, number: int) -> dict[str, Any]:
        assert repository == REPOSITORY and number == 42
        return {
            "number": 42,
            "state": "open",
            "title": "Harden workflow permissions fallback",
            "body": "Use an exact generated branch when Actions cannot open a PR.",
            "head": {"sha": HEAD, "ref": self.head_ref},
            "base": {"sha": BASE, "ref": "main"},
        }

    def files(self, repository: str, number: int) -> list[dict[str, Any]]:
        assert repository == REPOSITORY and number == 42
        return [
            {
                "filename": filename,
                "status": "modified",
                "additions": 1,
                "deletions": 1,
            }
            for filename in self.filenames
        ]

    def repository(self, repository: str) -> dict[str, Any]:
        return {"visibility": self.visibility}

    def directory(self, repository: str, path: str, ref: str) -> list[dict[str, Any]]:
        assert path == core.MEMORY_ROOT and ref == BASE
        return [
            {"type": "file", "path": memory_path}
            for memory_path in sorted(self.packs)
        ]

    def content(self, repository: str, path: str, ref: str) -> dict[str, Any]:
        raw = json.dumps(self.packs[path]).encode()
        return {
            "encoding": "base64",
            "size": len(raw),
            "content": base64.b64encode(raw).decode(),
        }

    def content_text(self, payload: dict[str, Any]) -> str:
        return base64.b64decode(payload["content"]).decode()

    def comments(self, repository: str, number: int) -> list[dict[str, Any]]:
        return list(self.comment_items)

    def create_comment(
        self, repository: str, number: int, body: str
    ) -> dict[str, Any]:
        self.created.append(body)
        comment = {
            "id": 100,
            "body": body,
            "user": {"login": github.BOT_LOGIN},
        }
        self.comment_items.append(comment)
        return comment

    def update_comment(
        self, repository: str, comment_id: int, body: str
    ) -> dict[str, Any]:
        self.updated.append((comment_id, body))
        for comment in self.comment_items:
            if comment["id"] == comment_id:
                comment["body"] = body
        return {"id": comment_id, "body": body}


def run(api: FakeApi) -> dict[str, Any]:
    return github.retrieve_for_pull(
        api=api,
        repository=REPOSITORY,
        pull_number=42,
        run_id=10,
        run_attempt=1,
        run_url="https://example.invalid/run/10",
    )


def test_adapter_creates_then_updates_one_managed_comment() -> None:
    path = f"{core.MEMORY_ROOT}/workflow.json"
    api = FakeApi(packs={path: workflow_pack()})

    first = run(api)
    second = run(api)

    assert first["outcome"] == "COMMENT_UPSERTED"
    assert first["comment_action"] == "created"
    assert first["selected"][0]["path"] == path
    assert first["direct_main_write"] is False
    assert first["approval_authority"] is False
    assert first["merge_authority"] is False
    assert first["execution_authority"] is False
    assert second["comment_action"] == "updated"
    assert len(api.created) == 1
    assert len(api.updated) == 1
    assert api.created[0].count(core.COMMENT_MARKER) == 1


def test_human_spoofed_marker_is_not_overwritten() -> None:
    path = f"{core.MEMORY_ROOT}/workflow.json"
    api = FakeApi(packs={path: workflow_pack()})
    api.comment_items = [
        {
            "id": 5,
            "body": core.COMMENT_MARKER + " spoof",
            "user": {"login": "human"},
        }
    ]

    result = run(api)

    assert result["comment_action"] == "created"
    assert api.updated == []
    assert len(api.created) == 1


def test_public_adapter_withholds_team_private_memory() -> None:
    path = f"{core.MEMORY_ROOT}/private.json"
    api = FakeApi(
        packs={
            path: workflow_pack(
                visibility="team", contains_private_data=True
            )
        }
    )

    result = run(api)

    assert result["accepted_count"] == 1
    assert result["publishable_count"] == 0
    assert result["withheld_count"] == 1
    assert result["selected"] == []
    assert "No publishable accepted memory" in api.created[0]
    assert "Repository workflow permissions" not in api.created[0]


def test_generated_memory_pull_is_skipped_without_comment() -> None:
    api = FakeApi(
        packs={},
        head_ref="cml-learning/pr-190-deadbeef",
        filenames=[f"{core.MEMORY_ROOT}/pr-190.json"],
    )

    result = run(api)

    assert result["outcome"] == "SKIPPED"
    assert result["skip_reason"] == "generated-memory-branch"
    assert api.created == []
    assert api.updated == []
