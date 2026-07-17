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

core = importlib.import_module("memory_learning_core")
fallback = importlib.import_module("memory_learning_fallback")
github = importlib.import_module("memory_learning_github")

REPOSITORY = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40
MERGE = "b" * 40
BRANCH = "cml-learning/pr-184-bbbbbbbbbbbb"
MEMORY_PATH = ".cml/memory/cycles/pr-184-bbbbbbbbbbbb.json"


def source_pull() -> dict[str, Any]:
    return {
        "number": 184,
        "title": "docs: live probe",
        "body": "## Summary\nProbe the loop.\n\n## Boundaries\nHuman review required.",
        "merged": True,
        "merged_at": "2026-07-17T10:21:54Z",
        "merge_commit_sha": MERGE,
        "html_url": "https://github.com/safal207/Causal-Memory-Layer/pull/184",
        "head": {"sha": HEAD, "ref": "agent/live-probe"},
        "base": {"ref": "main"},
    }


def source_files() -> list[dict[str, Any]]:
    return [
        {
            "filename": "docs/verification/probe.md",
            "status": "added",
            "additions": 10,
            "deletions": 0,
        }
    ]


def generated_pack() -> dict[str, Any]:
    return core.build_memory_pack(
        repository=REPOSITORY,
        pull=source_pull(),
        files=source_files(),
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


def encode_pack(pack: dict[str, Any]) -> dict[str, str]:
    text = json.dumps(pack, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return {
        "encoding": "base64",
        "content": base64.b64encode(text.encode()).decode(),
    }


class FakeApi:
    def __init__(self, *, pack: dict[str, Any] | None = None) -> None:
        self.pack = pack or generated_pack()
        self.issue_items: list[dict[str, Any]] = []
        self.created_issues: list[dict[str, Any]] = []

    def pull(self, repository: str, number: int):
        assert repository == REPOSITORY and number == 184
        return source_pull()

    def files(self, repository: str, number: int):
        assert repository == REPOSITORY and number == 184
        return source_files()

    def content(self, repository: str, path: str, ref: str):
        assert repository == REPOSITORY and path == MEMORY_PATH
        if ref == "main":
            return None
        assert ref == BRANCH
        return encode_pack(self.pack)

    def ref(self, repository: str, branch: str):
        assert repository == REPOSITORY and branch == BRANCH
        return {"object": {"sha": "c" * 40}}

    def content_text(self, payload: dict[str, str]) -> str:
        return base64.b64decode(payload["content"]).decode()

    def paginated(self, path: str):
        assert path == f"/repos/{REPOSITORY}/issues?state=all"
        return self.issue_items

    def json(self, method: str, path: str, *, payload, expected):
        assert method == "POST"
        assert path == f"/repos/{REPOSITORY}/issues"
        assert expected == (201,)
        self.created_issues.append(payload)
        return {
            "number": 300,
            "html_url": "https://example.invalid/issues/300",
            "title": payload["title"],
        }


def blocked_error() -> core.LearningLoopError:
    return core.LearningLoopError(
        "GitHub API returned 403 for POST "
        f"/repos/{REPOSITORY}/pulls: "
        '{"message":"GitHub Actions is not permitted to create or approve pull requests."}'
    )


def run_fallback(monkeypatch: pytest.MonkeyPatch, api: FakeApi):
    def fail(**kwargs):
        raise blocked_error()

    monkeypatch.setattr(github, "propose", fail)
    return fallback.propose_with_fallback(
        api=api,
        repository=REPOSITORY,
        pull_number=184,
        run_id=10,
        run_attempt=1,
        run_url="https://example.invalid/runs/10/attempts/1",
    )


def test_exact_actions_pr_block_creates_idempotent_review_issue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = FakeApi()

    result = run_fallback(monkeypatch, api)

    assert result["outcome"] == "PROPOSAL_BRANCH_CREATED_PR_BLOCKED"
    assert result["branch"] == BRANCH
    assert result["memory_path"] == MEMORY_PATH
    assert result["memory_pack_id"] == api.pack["pack_id"]
    assert result["fallback_issue_number"] == 300
    assert result["validation_dispatched"] is False
    assert result["direct_main_write"] is False
    assert result["merge_authority"] is False
    assert result["execution_authority"] is False
    assert len(api.created_issues) == 1
    body = api.created_issues[0]["body"]
    assert HEAD in body and MERGE in body and api.pack["pack_id"] in body

    api.issue_items = [
        {
            "number": 301,
            "html_url": "https://example.invalid/issues/301",
            "title": "memory proposal blocked for merged PR #184",
        }
    ]
    api.created_issues.clear()
    replay = run_fallback(monkeypatch, api)
    assert replay["fallback_issue_number"] == 301
    assert api.created_issues == []


def test_unrelated_403_remains_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    api = FakeApi()

    def fail(**kwargs):
        raise core.LearningLoopError(
            f"GitHub API returned 403 for POST /repos/{REPOSITORY}/pulls: forbidden"
        )

    monkeypatch.setattr(github, "propose", fail)
    with pytest.raises(core.LearningLoopError, match="forbidden"):
        fallback.propose_with_fallback(
            api=api,
            repository=REPOSITORY,
            pull_number=184,
            run_id=10,
            run_attempt=1,
            run_url="https://example.invalid/run",
        )
    assert api.created_issues == []


def test_tampered_pack_is_rejected_before_issue_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tampered = generated_pack()
    tampered["graph"]["nodes"][0]["confidence"] = 1
    api = FakeApi(pack=tampered)

    with pytest.raises(core.LearningLoopError, match="identity mismatch"):
        run_fallback(monkeypatch, api)
    assert api.created_issues == []


def test_unsafe_authority_boundary_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsafe = generated_pack()
    unsafe["manifest"]["merge_authority"] = True
    unsafe["pack_id"] = core.sha256_json(core.canonical_preimage(unsafe))
    api = FakeApi(pack=unsafe)

    with pytest.raises(core.LearningLoopError, match="unsafe manifest"):
        run_fallback(monkeypatch, api)
    assert api.created_issues == []


def test_fallback_is_protected_and_least_privilege() -> None:
    workflow = (ROOT / ".github/workflows/memory-learning-loop.yml").read_text(
        encoding="utf-8"
    )
    entrypoint = (
        ROOT / ".github/trust-root/scripts/memory_learning_loop.py"
    ).read_text(encoding="utf-8")
    fallback_text = (
        ROOT / ".github/trust-root/scripts/memory_learning_fallback.py"
    ).read_text(encoding="utf-8")

    assert "issues: write" in workflow
    assert "contents: write" in workflow
    assert "pull-requests: write" in workflow
    assert "memory_learning_fallback" in entrypoint
    assert "propose_with_fallback" in entrypoint
    assert "PR_CREATION_BLOCKED" in fallback_text
    assert "GitHub API returned 403" in fallback_text
    assert '"outcome": "PROPOSAL_BRANCH_CREATED_PR_BLOCKED"' in fallback_text
    assert "direct_main_write" not in fallback_text
    assert "subprocess" not in fallback_text
    assert "eval(" not in fallback_text
    assert "exec(" not in fallback_text
