from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / ".github/trust-root/scripts/reviewer_fallback_entrypoint.py"
SPEC = importlib.util.spec_from_file_location("reviewer_fallback_surfaces", MODULE_PATH)
assert SPEC and SPEC.loader
rf = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rf
SPEC.loader.exec_module(rf)

REPO = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40
NOW = "2026-07-15T12:00:00+00:00"
LATER = "2026-07-15T12:01:00+00:00"


def identity(login: str, user_id: int) -> dict[str, object]:
    return {"login": login, "id": user_id}


def provider_identity(provider: str) -> dict[str, object]:
    if provider == "coderabbit":
        return identity(rf.CODE_RABBIT_LOGIN, rf.CODE_RABBIT_ID)
    if provider == "qodo":
        return identity(rf.QODO_LOGIN, rf.QODO_ID)
    raise AssertionError(provider)


def raw_event(
    event_name: str,
    *,
    provider: str = "coderabbit",
    body: str = "Review limit reached",
    action: str | None = None,
    comment_id: int = 101,
    user: dict[str, object] | None = None,
    sender: dict[str, object] | None = None,
) -> dict[str, object]:
    actor = user or provider_identity(provider)
    sender = sender or actor
    repository = {"full_name": REPO}
    pull = {
        "number": 77,
        "url": f"https://api.github.com/repos/{REPO}/pulls/77",
    }
    if event_name == "issue_comment":
        return {
            "action": action or "created",
            "repository": repository,
            "issue": {"number": 77, "pull_request": {"url": pull["url"]}},
            "comment": {
                "id": comment_id,
                "body": body,
                "user": actor,
                "created_at": NOW,
            },
            "sender": sender,
        }
    if event_name == "pull_request_review":
        return {
            "action": action or "submitted",
            "repository": repository,
            "pull_request": pull,
            "review": {
                "id": comment_id,
                "body": body,
                "user": actor,
                "submitted_at": NOW,
            },
            "sender": sender,
        }
    if event_name == "pull_request_review_comment":
        return {
            "action": action or "created",
            "repository": repository,
            "pull_request": pull,
            "comment": {
                "id": comment_id,
                "body": body,
                "user": actor,
                "created_at": NOW,
            },
            "sender": sender,
        }
    raise AssertionError(event_name)


class SurfaceClient:
    def __init__(self) -> None:
        self.comments: list[dict[str, object]] = []
        self.created: list[dict[str, object]] = []
        self.updated: list[dict[str, object]] = []
        self.statuses: list[dict[str, object]] = []
        self.artifacts: dict[tuple[int, int], dict[str, object]] = {}
        self.next_id = 1000

    def get_pull(self, repository: str, pull_number: int) -> dict[str, object]:
        assert repository == REPO and pull_number == 77
        return {
            "state": "open",
            "base": {"ref": "main"},
            "head": {"sha": HEAD},
        }

    def list_comments(self, repository: str, pull_number: int):
        assert repository == REPO and pull_number == 77
        return list(self.comments)

    def create_comment(self, repository: str, pull_number: int, body: str):
        assert repository == REPO and pull_number == 77
        comment = {
            "id": self.next_id,
            "body": body,
            "user": identity(rf.ACTIONS_LOGIN, rf.ACTIONS_ID),
            "created_at": NOW,
        }
        self.next_id += 1
        self.comments.append(comment)
        self.created.append(copy.deepcopy(comment))
        return comment

    def update_comment(self, repository: str, comment_id: int, body: str):
        assert repository == REPO
        for comment in self.comments:
            if comment["id"] == comment_id:
                comment["body"] = body
                self.updated.append(copy.deepcopy(comment))
                return comment
        raise AssertionError("missing comment")

    def create_status(
        self,
        repository: str,
        head_sha: str,
        *,
        state: str,
        description: str,
        target_url: str,
    ):
        assert repository == REPO
        status = {
            "head_sha": head_sha,
            "state": state,
            "description": description,
            "target_url": target_url,
        }
        self.statuses.append(status)
        return status

    def load_fallback_artifact(
        self, repository: str, pull_number: int, run_id: int, run_attempt: int
    ):
        assert repository == REPO and pull_number == 77
        try:
            return copy.deepcopy(self.artifacts[(run_id, run_attempt)])
        except KeyError as exc:
            raise rf.FallbackError("authenticated fallback artifact missing") from exc


def run_surface(
    event_name: str,
    payload: dict[str, object],
    client: SurfaceClient,
    *,
    run_id: int,
    run_attempt: int = 1,
):
    normalized = rf.normalize_event_payload(event_name, payload)
    result = rf.process_event(
        normalized,
        client,
        repository=REPO,
        run_id=run_id,
        run_attempt=run_attempt,
        run_url=f"https://github.com/{REPO}/actions/runs/{run_id}/attempts/{run_attempt}",
        now=lambda: NOW,
    )
    client.artifacts[(run_id, run_attempt)] = copy.deepcopy(result)
    return normalized, result


@pytest.mark.parametrize(
    "event_name",
    ["issue_comment", "pull_request_review", "pull_request_review_comment"],
)
def test_coderabbit_rate_limit_on_each_native_surface_requests_qodo_once(
    event_name: str,
) -> None:
    client = SurfaceClient()

    normalized, result = run_surface(
        event_name, raw_event(event_name), client, run_id=123
    )

    assert normalized["cml_original_event_name"] == event_name
    assert result["passed"] is True
    assert result["outcome"] == "QODO_REQUESTED_EXACT_HEAD"
    requests = [
        comment
        for comment in client.comments
        if str(comment["body"]).startswith("/qodo review")
    ]
    assert len(requests) == 1
    assert HEAD in str(requests[0]["body"])
    assert client.statuses == []


def test_qodo_review_submission_can_complete_authenticated_lifecycle() -> None:
    client = SurfaceClient()
    run_surface(
        "pull_request_review", raw_event("pull_request_review"), client, run_id=100
    )

    body = f"Review bound to exact head `{HEAD}`.\nBugs (0)"
    normalized, result = run_surface(
        "pull_request_review",
        raw_event(
            "pull_request_review",
            provider="qodo",
            body=body,
            comment_id=700,
        ),
        client,
        run_id=200,
    )

    assert normalized["action"] == "created"
    assert result["outcome"] == "QODO_REVIEW_RECORDED"
    assert result["final_qodo_review_sha"] == HEAD
    assert result["final_qodo_outcome"] == "NO_ACTIONABLE_FINDINGS"
    assert result["merge_authority"] is False


def test_inline_qodo_comment_cannot_complete_lifecycle() -> None:
    client = SurfaceClient()
    run_surface("issue_comment", raw_event("issue_comment"), client, run_id=100)

    normalized, result = run_surface(
        "pull_request_review_comment",
        raw_event(
            "pull_request_review_comment",
            provider="qodo",
            body=f"Review bound to exact head `{HEAD}`.\nBugs (0)",
            comment_id=701,
        ),
        client,
        run_id=200,
    )

    assert normalized["action"] == "edited"
    assert result["passed"] is False
    assert result["outcome"] == "REJECTED_EDITED_QODO_RESULT"


def test_review_surface_preserves_sender_author_disagreement_for_core_rejection() -> None:
    client = SurfaceClient()
    canonical_author = provider_identity("coderabbit")
    spoofed_sender = identity(rf.CODE_RABBIT_LOGIN, 999)

    _, result = run_surface(
        "pull_request_review",
        raw_event(
            "pull_request_review",
            user=canonical_author,
            sender=spoofed_sender,
        ),
        client,
        run_id=123,
    )

    assert result["outcome"] == "IGNORED_UNRELATED_COMMENT"
    assert client.comments == []
    assert client.statuses == []


def test_unsupported_event_surface_fails_closed() -> None:
    with pytest.raises(rf.FallbackError, match="unsupported reviewer fallback event"):
        rf.normalize_event_payload("workflow_dispatch", {})
