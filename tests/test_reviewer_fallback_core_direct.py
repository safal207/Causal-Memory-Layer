from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / ".github/trust-root/scripts/reviewer_fallback.py"
SPEC = importlib.util.spec_from_file_location("reviewer_fallback_core_direct", CORE_PATH)
assert SPEC and SPEC.loader
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
SPEC.loader.exec_module(core)

REPO = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40


def identity(login: str, user_id: int):
    return {"login": login, "id": user_id}


def edited_qodo_event():
    return {
        "action": "edited",
        "repository": {"full_name": REPO},
        "issue": {"number": 77, "pull_request": {"url": "https://example.test/pr/77"}},
        "comment": {
            "id": 700,
            "body": f"Review bound to exact head `{HEAD}`.\nBugs (0)",
            "created_at": "2026-07-14T12:01:00+00:00",
            "user": identity(core.QODO_LOGIN, core.QODO_ID),
        },
        "sender": identity(core.QODO_LOGIN, core.QODO_ID),
    }


def test_direct_core_rejects_edited_qodo_result_without_client_calls():
    result = core.process_event(
        edited_qodo_event(),
        object(),
        repository=REPO,
        run_id=200,
        run_attempt=1,
        run_url="https://example.test/run/200/attempt/1",
    )
    assert result["passed"] is False
    assert result["outcome"] == "REJECTED_EDITED_QODO_RESULT"
    assert result["merge_authority"] is False


def test_direct_core_requires_exactly_one_structured_reviewed_sha_occurrence():
    with pytest.raises(core.FallbackError, match="exactly one"):
        core._extract_reviewed_sha(
            f"Review bound to exact head `{HEAD}`.\nReviewed commit: `{HEAD}`"
        )


def test_direct_core_never_publishes_a_success_commit_status():
    class Client:
        def __init__(self):
            self.statuses = []

        def create_status(self, *args, **kwargs):
            self.statuses.append((args, kwargs))

    client = Client()
    core._publish_commit_status(
        client,
        repository=REPO,
        head_sha=HEAD,
        evidence={
            "passed": True,
            "outcome": "QODO_REVIEW_RECORDED",
            "event_run_url": "https://example.test/run/200/attempt/1",
        },
    )
    assert client.statuses == []


def test_direct_core_artifact_pagination_exhaustion_fails_closed():
    api = object.__new__(core.GitHubApi)
    api._token = "token"

    def request_json(method, url, *, payload=None):
        assert method == "GET" and payload is None
        if url.endswith("/actions/runs/123"):
            return {
                "name": core.WORKFLOW_NAME,
                "event": "issue_comment",
                "path": core.WORKFLOW_PATH,
                "head_branch": "main",
                "run_attempt": 2,
                "repository": {"full_name": REPO},
                "status": "completed",
                "conclusion": "success",
            }
        if "/actions/runs/123/artifacts?" in url:
            return {
                "artifacts": [
                    {"id": index, "name": f"noise-{index}", "expired": False}
                    for index in range(100)
                ]
            }
        raise AssertionError(url)

    api._request_json = request_json
    with pytest.raises(core.FallbackError, match="pagination exceeded"):
        api.load_fallback_artifact(REPO, 77, 123, 2)


def test_direct_cli_main_uses_the_same_strict_core_functions():
    source = CORE_PATH.read_text(encoding="utf-8")
    assert "client = GitHubApi(" in source
    assert "result = process_event(" in source
    assert 'if __name__ == "__main__":' in source
    assert "main()" in source
