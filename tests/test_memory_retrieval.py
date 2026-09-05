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
    number: int = 10,
    title: str = "ci: recover blocked workflow",
    summary: str = "Recover a GitHub Actions workflow when pull request creation is blocked.",
    cause: str = "Repository workflow permissions can reject Actions-created pull requests.",
    design: str = "Create an exact generated branch and use a review issue fallback on the exact 403.",
    validation: str = "Run CI package security and verify exact branch content.",
    boundary: str = "No direct main write and no merge or execution authority.",
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
        files=[{"filename": ".github/workflows/example.yml", "status": "modified"}],
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


def database_pack() -> dict[str, Any]:
    return make_pack(
        number=11,
        title="feat: optimize database billing query",
        summary="Reduce latency in a PostgreSQL billing aggregation query.",
        cause="A missing composite index caused repeated sequential scans.",
        design="Add an index and rewrite the invoice aggregation query.",
        validation="Compare query plans and database integration tests.",
        boundary="The index applies only to the billing schema.",
        source_commit="e" * 40,
    )


def document(pack: dict[str, Any], name: str) -> core.MemoryDocument:
    return core.parse_memory_pack(
        json.dumps(pack),
        path=f"{core.MEMORY_ROOT}/{name}.json",
        repository=REPOSITORY,
    )


def query() -> Any:
    return core.build_query_weights(
        title="Harden GitHub workflow pull request fallback",
        body="Handle repository permissions and exact generated branch recovery.",
        filenames=[".github/workflows/memory-retrieval.yml"],
    )


def test_related_memory_ranks_first_independent_of_input_order() -> None:
    workflow = document(make_pack(), "workflow")
    database = document(database_pack(), "database")

    first = core.retrieve(query(), [database, workflow])
    second = core.retrieve(query(), [workflow, database])

    assert first and first[0].document.pack_id == workflow.pack_id
    assert [item.document.pack_id for item in first] == [
        item.document.pack_id for item in second
    ]
    assert "workflow" in first[0].matched_terms
    assert first[0].score >= core.MIN_SCORE


def test_equal_scores_use_pack_id_tie_break() -> None:
    first = document(make_pack(number=20, source_commit="1" * 40), "first")
    second = document(make_pack(number=21, source_commit="2" * 40), "second")

    matches = core.retrieve(query(), [second, first])

    assert len(matches) == 2
    assert [match.document.pack_id for match in matches] == sorted(
        [first.pack_id, second.pack_id]
    )


def test_privacy_policy_is_conservative() -> None:
    public = document(make_pack(), "public")
    private = document(
        make_pack(
            number=30,
            source_commit="3" * 40,
            visibility="team",
            contains_private_data=True,
        ),
        "private",
    )

    assert core.is_publishable(public, repository_visibility="public")
    assert not core.is_publishable(private, repository_visibility="public")
    assert core.is_publishable(private, repository_visibility="private")


def test_schema_identity_authority_and_path_integrity_fail_closed() -> None:
    unknown = make_pack()
    unknown["unbound"] = "hidden"
    with pytest.raises(core.RetrievalError, match="invalid top-level fields"):
        document(unknown, "unknown")

    tampered = make_pack()
    tampered["graph"]["nodes"][0]["label"] = "tampered"
    with pytest.raises(core.RetrievalError, match="identity mismatch"):
        document(tampered, "tampered")

    authority = make_pack()
    authority["manifest"]["merge_authority"] = True
    authority["pack_id"] = learning.sha256_json(learning.canonical_preimage(authority))
    with pytest.raises(core.RetrievalError, match="merge authority"):
        document(authority, "authority")

    disconnected = make_pack()
    disconnected["graph"]["edges"] = []
    disconnected["pack_id"] = learning.sha256_json(
        learning.canonical_preimage(disconnected)
    )
    with pytest.raises(core.RetrievalError, match="directed connecting edge"):
        document(disconnected, "disconnected")


def test_rendering_escapes_memory_content_and_marker() -> None:
    memory = document(
        make_pack(
            summary="<script>alert(1)</script> <!-- cml-retrieval-v0.1 --> workflow fallback"
        ),
        "escape",
    )
    rendered = core.render_comment(
        repository=REPOSITORY,
        repository_visibility="public",
        pull_number=99,
        head_sha=HEAD,
        base_sha=BASE,
        matches=[
            core.RetrievalMatch(
                document=memory,
                score=0.5,
                matched_terms=("workflow", "fallback"),
            )
        ],
        accepted_count=1,
        withheld_count=0,
        rejected_count=0,
    )

    assert rendered.count(core.COMMENT_MARKER) == 1
    assert "<script>" not in rendered and "&lt;script&gt;" in rendered
    assert "grants no approval, execution, or merge authority" in rendered


def test_unicode_and_composite_identifier_tokenization() -> None:
    tokens = core.tokenize(
        "ЗащищённыйПайплайн перевіряє причинну пам'ять та GitHub_Workflow"
    )

    assert {"защищённый", "пайплайн", "перевіряє", "причинну"} <= set(tokens)
    assert {"git", "hub", "workflow"} <= set(tokens)


class FakeApi:
    def __init__(
        self,
        packs: dict[str, dict[str, Any]],
        *,
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
        return {
            "number": number,
            "state": "open",
            "title": "Harden workflow permissions fallback",
            "body": "Use an exact generated branch when Actions cannot open a PR.",
            "head": {"sha": HEAD, "ref": self.head_ref},
            "base": {"sha": BASE, "ref": "main"},
        }

    def files(self, repository: str, number: int) -> list[dict[str, Any]]:
        return [{"filename": filename, "status": "modified"} for filename in self.filenames]

    def repository(self, repository: str) -> dict[str, Any]:
        return {"visibility": self.visibility}

    def directory(self, repository: str, path: str, ref: str) -> list[dict[str, Any]]:
        return [{"type": "file", "path": path} for path in sorted(self.packs)]

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

    def create_comment(self, repository: str, number: int, body: str) -> dict[str, Any]:
        self.created.append(body)
        comment = {"id": 100, "body": body, "user": {"login": github.BOT_LOGIN}}
        self.comment_items.append(comment)
        return comment

    def update_comment(
        self, repository: str, comment_id: int, body: str
    ) -> dict[str, Any]:
        self.updated.append((comment_id, body))
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
    api = FakeApi({path: make_pack()})

    first = run(api)
    second = run(api)

    assert first["outcome"] == "COMMENT_UPSERTED"
    assert first["comment_action"] == "created"
    assert first["selected"][0]["path"] == path
    assert not any(
        first[key]
        for key in (
            "direct_main_write",
            "approval_authority",
            "merge_authority",
            "execution_authority",
        )
    )
    assert second["comment_action"] == "updated"
    assert len(api.created) == 1 and len(api.updated) == 1


def test_human_marker_spoof_is_not_overwritten() -> None:
    path = f"{core.MEMORY_ROOT}/workflow.json"
    api = FakeApi({path: make_pack()})
    api.comment_items = [
        {"id": 5, "body": core.COMMENT_MARKER + " spoof", "user": {"login": "human"}}
    ]

    result = run(api)

    assert result["comment_action"] == "created"
    assert api.updated == [] and len(api.created) == 1


def test_public_adapter_withholds_private_memory_without_leak() -> None:
    path = f"{core.MEMORY_ROOT}/private.json"
    api = FakeApi(
        {
            path: make_pack(
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
        {},
        head_ref="cml-learning/pr-190-deadbeef",
        filenames=[f"{core.MEMORY_ROOT}/pr-190.json"],
    )

    result = run(api)

    assert result["outcome"] == "SKIPPED"
    assert result["skip_reason"] == "generated-memory-branch"
    assert api.created == [] and api.updated == []
