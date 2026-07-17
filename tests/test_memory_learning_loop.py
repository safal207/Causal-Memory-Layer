from __future__ import annotations

import base64
import importlib
import json
from pathlib import Path
import sys
from typing import Any

import pytest

from cml.integrations import memory_pack_from_mapping, verify_memory_pack

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".github/trust-root/scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

core = importlib.import_module("memory_learning_core")
github = importlib.import_module("memory_learning_github")

REPOSITORY = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40
MERGE = "b" * 40
BRANCH = "cml-learning/pr-181-bbbbbbbbbbbb"
MEMORY_PATH = ".cml/memory/cycles/pr-181-bbbbbbbbbbbb.json"


def pull(*, body: str | None = None, head_ref: str = "feature/example") -> dict[str, Any]:
    return {
        "number": 181,
        "title": "feat: add portable memory",
        "body": body
        if body is not None
        else """## Summary
Store a portable decision graph.

## Root cause
Earlier cycles recorded events but not the selected path.

## Design
Create a deterministic Memory Pack and require review before acceptance.

## Validation
Run CI, package validation, security, and independent review.

## Boundaries
The generated memory remains advisory and private by default.
""",
        "merged": True,
        "merged_at": "2026-07-17T09:00:00Z",
        "merge_commit_sha": MERGE,
        "html_url": "https://github.com/safal207/Causal-Memory-Layer/pull/181",
        "head": {"sha": HEAD, "ref": head_ref},
        "base": {"ref": "main"},
    }


def files() -> list[dict[str, Any]]:
    return [
        {
            "filename": "cml/integrations/memory_pack.py",
            "status": "added",
            "additions": 10,
            "deletions": 0,
        },
        {
            "filename": "tests/test_memory_pack.py",
            "status": "added",
            "additions": 5,
            "deletions": 0,
        },
    ]


def reviews() -> list[dict[str, Any]]:
    return [
        {
            "id": 1,
            "state": "COMMENTED",
            "commit_id": HEAD,
            "submitted_at": "2026-07-17T08:50:00Z",
            "body": "UNTRUSTED REVIEW BODY MUST NOT ENTER MEMORY",
            "user": {"login": "reviewer[bot]"},
        }
    ]


def checks() -> list[dict[str, Any]]:
    return [
        {
            "name": "CI",
            "status": "completed",
            "conclusion": "success",
            "details_url": "https://example.invalid/check/2",
        },
        {
            "name": "CI",
            "status": "completed",
            "conclusion": "success",
            "details_url": "https://example.invalid/check/1",
        },
    ]


def rendered_pack() -> str:
    pack = core.build_memory_pack(
        repository=REPOSITORY,
        pull=pull(),
        files=files(),
        reviews=reviews(),
        check_runs=checks(),
    )
    return json.dumps(pack, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def encoded_content(text: str, *, line_wrapped: bool = False) -> dict[str, str]:
    encoded = base64.b64encode(text.encode()).decode()
    if line_wrapped:
        encoded = "\n".join(
            encoded[index : index + 24]
            for index in range(0, len(encoded), 24)
        )
    return {"encoding": "base64", "content": encoded}


class FakeApi:
    def __init__(self) -> None:
        self.pull_payload = pull()
        self.file_payload = files()
        self.proposal_file_payload: list[dict[str, Any]] = [
            {
                "filename": MEMORY_PATH,
                "status": "added",
                "additions": 1,
                "deletions": 0,
            }
        ]
        self.review_payload = reviews()
        self.check_payload = checks()
        self.main_content: dict[str, Any] | None = None
        self.branch_content: dict[str, Any] | None = None
        self.branch_ref: dict[str, Any] | None = None
        self.proposal_payload: dict[str, Any] | None = None
        self.created_refs: list[tuple[str, str]] = []
        self.created_contents: list[dict[str, str]] = []
        self.created_pulls: list[dict[str, str]] = []
        self.dispatched: list[tuple[str, str]] = []

    def pull(self, repository: str, number: int):
        assert repository == REPOSITORY and number == 181
        return self.pull_payload

    def files(self, repository: str, number: int):
        assert repository == REPOSITORY
        if number == 181:
            return self.file_payload
        if number == 200:
            return self.proposal_file_payload
        raise AssertionError(f"unexpected pull number: {number}")

    def reviews(self, repository: str, number: int):
        assert repository == REPOSITORY and number == 181
        return self.review_payload

    def checks(self, repository: str, sha: str):
        assert repository == REPOSITORY and sha == HEAD
        return self.check_payload

    def content(self, repository: str, path: str, ref: str):
        assert repository == REPOSITORY and path == MEMORY_PATH
        if ref == "main":
            return self.main_content
        assert ref == BRANCH
        return self.branch_content

    def proposal(self, repository: str, branch: str):
        assert repository == REPOSITORY and branch == BRANCH
        return self.proposal_payload

    def ref(self, repository: str, branch: str):
        assert repository == REPOSITORY and branch == BRANCH
        return self.branch_ref

    def create_ref(self, repository: str, branch: str, sha: str) -> None:
        assert repository == REPOSITORY
        self.created_refs.append((branch, sha))
        self.branch_ref = {"object": {"sha": sha}}

    def create_content(
        self,
        repository: str,
        *,
        path: str,
        branch: str,
        message: str,
        text: str,
    ) -> None:
        assert repository == REPOSITORY
        self.created_contents.append(
            {"path": path, "branch": branch, "message": message, "text": text}
        )
        self.branch_content = encoded_content(text)

    def content_text(self, payload: dict[str, Any]) -> str:
        normalized = "".join(payload["content"].split())
        return base64.b64decode(normalized, validate=True).decode()

    def create_pull(
        self,
        repository: str,
        *,
        title: str,
        branch: str,
        body: str,
    ):
        assert repository == REPOSITORY
        self.created_pulls.append({"title": title, "branch": branch, "body": body})
        return {
            "number": 200,
            "html_url": "https://example.invalid/pull/200",
            "state": "open",
        }

    def dispatch_validation(self, repository: str, branch: str) -> None:
        self.dispatched.append((repository, branch))


def propose(api: FakeApi):
    return github.propose(
        api=api,
        repository=REPOSITORY,
        pull_number=181,
        run_id=10,
        run_attempt=1,
        run_url="https://example.invalid/runs/10/attempts/1",
    )


def test_generated_pack_is_valid_deterministic_and_private_by_default() -> None:
    first = core.build_memory_pack(
        repository=REPOSITORY,
        pull=pull(),
        files=files(),
        reviews=reviews(),
        check_runs=checks(),
    )
    second = core.build_memory_pack(
        repository=REPOSITORY,
        pull=pull(),
        files=list(reversed(files())),
        reviews=list(reversed(reviews())),
        check_runs=list(reversed(checks())),
    )

    assert first["pack_id"] == second["pack_id"]
    assert first["manifest"]["created_at"] == "2026-07-17T09:00:00.000Z"
    assert first["manifest"]["visibility"] == "team"
    assert first["manifest"]["contains_private_data"] is True
    assert first["manifest"]["merge_authority"] is False
    assert first["manifest"]["execution_authority"] is False
    assert "UNTRUSTED REVIEW BODY" not in json.dumps(first)

    loaded = memory_pack_from_mapping(first)
    assert verify_memory_pack(loaded).passed()
    assert loaded.graph.selected_path[0] == "situation-merged-pr"
    assert loaded.graph.selected_path[-1] == "lesson-proposed-best-known-path"
    lesson = next(node for node in loaded.graph.nodes if node.kind == "lesson")
    assert lesson.status == "proposed"
    assert lesson.attributes["human_review_required"] is True


def test_explicit_root_cause_is_used_but_not_invented() -> None:
    with_cause = core.build_memory_pack(
        repository=REPOSITORY,
        pull=pull(),
        files=files(),
        reviews=reviews(),
        check_runs=checks(),
    )
    without_cause = core.build_memory_pack(
        repository=REPOSITORY,
        pull=pull(body="## Summary\nA small change.\n\n## Design\nApply it."),
        files=files(),
        reviews=[],
        check_runs=[],
    )

    cause_nodes = [
        node for node in with_cause["graph"]["nodes"] if node["kind"] == "cause"
    ]
    assert len(cause_nodes) == 1
    assert cause_nodes[0]["attributes"]["inference"] is False
    assert not [
        node for node in without_cause["graph"]["nodes"] if node["kind"] == "cause"
    ]


def test_recursion_and_memory_only_changes_are_skipped() -> None:
    assert (
        core.should_skip(pull(head_ref="cml-learning/pr-181-deadbeef"), files())
        == "generated-memory-branch"
    )
    generated_title = pull()
    generated_title["title"] = "memory: learn from merged PR #181"
    assert core.should_skip(generated_title, files()) == "generated-memory-title"
    assert (
        core.should_skip(pull(), [{"filename": ".cml/memory/cycles/pr-1.json"}])
        == "memory-only-change"
    )


def test_first_delivery_creates_reviewable_branch_not_main_and_dispatches_validation() -> None:
    api = FakeApi()
    result = propose(api)

    assert result["outcome"] == "PROPOSAL_CREATED"
    assert result["direct_main_write"] is False
    assert result["merge_authority"] is False
    assert result["execution_authority"] is False
    assert result["validation_dispatched"] is True
    assert api.created_refs == [(BRANCH, MERGE)]
    assert len(api.created_contents) == 1
    assert api.created_contents[0]["path"] == MEMORY_PATH
    assert api.created_contents[0]["branch"] == BRANCH
    assert api.created_contents[0]["branch"] != "main"
    assert len(api.created_pulls) == 1
    assert api.created_pulls[0]["title"] == "memory: learn from merged PR #181"
    assert api.dispatched == [(REPOSITORY, BRANCH)]
    pack = json.loads(api.created_contents[0]["text"])
    assert verify_memory_pack(memory_pack_from_mapping(pack)).passed()


def test_open_proposal_is_idempotent_only_for_exact_single_file_content() -> None:
    api = FakeApi()
    api.proposal_payload = {
        "number": 200,
        "html_url": "https://example.invalid/pull/200",
        "state": "open",
    }
    api.branch_content = encoded_content(rendered_pack(), line_wrapped=True)

    result = propose(api)

    assert result["outcome"] == "PROPOSAL_ALREADY_OPEN_NOOP"
    assert result["validation_dispatched"] is True
    assert api.created_refs == []
    assert api.created_contents == []
    assert api.created_pulls == []
    assert api.dispatched == [(REPOSITORY, BRANCH)]


def test_open_proposal_with_wrong_content_fails_closed() -> None:
    api = FakeApi()
    api.proposal_payload = {
        "number": 200,
        "html_url": "https://example.invalid/pull/200",
        "state": "open",
    }
    api.branch_content = encoded_content("{}\n")

    with pytest.raises(core.LearningLoopError, match="exact expected memory pack"):
        propose(api)

    assert api.dispatched == []


def test_open_proposal_with_extra_files_fails_closed() -> None:
    api = FakeApi()
    api.proposal_payload = {
        "number": 200,
        "html_url": "https://example.invalid/pull/200",
        "state": "open",
    }
    api.branch_content = encoded_content(rendered_pack())
    api.proposal_file_payload.append(
        {
            "filename": "unexpected.txt",
            "status": "added",
            "additions": 1,
            "deletions": 0,
        }
    )

    with pytest.raises(core.LearningLoopError, match="unexpected changed files"):
        propose(api)

    assert api.dispatched == []


def test_closed_proposal_is_not_recreated() -> None:
    api = FakeApi()
    api.proposal_payload = {
        "number": 200,
        "html_url": "https://example.invalid/pull/200",
        "state": "closed",
    }

    result = propose(api)

    assert result["outcome"] == "PROPOSAL_CLOSED_NOOP"
    assert api.created_refs == []
    assert api.created_contents == []
    assert api.created_pulls == []
    assert api.dispatched == []


def test_already_accepted_memory_is_noop() -> None:
    api = FakeApi()
    api.main_content = {"sha": "existing"}

    result = propose(api)

    assert result["outcome"] == "ALREADY_ACCEPTED_NOOP"
    assert api.created_refs == []
    assert api.created_pulls == []


def test_existing_branch_with_different_content_fails_closed() -> None:
    api = FakeApi()
    api.branch_ref = {"object": {"sha": "c" * 40}}
    api.branch_content = encoded_content("{}\n")

    with pytest.raises(core.LearningLoopError, match="different memory proposal"):
        propose(api)


def test_real_content_decoder_accepts_github_line_wrapped_base64() -> None:
    api = github.GitHubApi("token")
    assert api.content_text(
        encoded_content("hello\n", line_wrapped=True)
    ) == "hello\n"


def test_workflow_is_protected_bounded_and_never_runs_pr_code() -> None:
    workflow = (ROOT / ".github/workflows/memory-learning-loop.yml").read_text(
        encoding="utf-8"
    )
    entrypoint = (
        ROOT / ".github/trust-root/scripts/memory_learning_loop.py"
    ).read_text(encoding="utf-8")
    adapter = (
        ROOT / ".github/trust-root/scripts/memory_learning_github.py"
    ).read_text(encoding="utf-8")

    assert "pull_request_target" not in workflow
    assert "pull_request:\n    branches: [main]\n    types: [closed]" in workflow
    assert "workflow_dispatch:" in workflow
    assert "github.event.pull_request.merged == true" in workflow
    assert (
        "ref: ${{ github.event.pull_request.merge_commit_sha || github.sha }}"
        in workflow
    )
    assert "persist-credentials: false" in workflow
    assert "permissions: {}" in workflow
    assert "actions: write" in workflow
    assert "checks: read" in workflow
    assert "contents: write" in workflow
    assert "pull-requests: write" in workflow
    assert "cancel-in-progress: true" in workflow
    assert "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10" in workflow
    assert "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1" in workflow
    assert (
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        in workflow
    )
    assert ".github/trust-root/scripts/memory_learning_loop.py" in workflow
    assert "github.event.pull_request.head" not in workflow
    assert "subprocess" not in entrypoint
    assert "eval(" not in entrypoint
    assert "exec(" not in entrypoint
    assert "REPOSITORY.fullmatch" in entrypoint
    assert '"branch": branch' in adapter
    assert '"base": "main"' in adapter
    assert "direct_main_write" in adapter
    assert "VALIDATION_WORKFLOWS" in adapter
    assert (
        "open generated proposal does not contain the exact expected memory pack"
        in adapter
    )
    assert "open generated proposal contains unexpected changed files" in adapter
