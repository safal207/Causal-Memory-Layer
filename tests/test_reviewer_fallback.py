from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / ".github/trust-root/scripts/reviewer_fallback_entrypoint.py"
SPEC = importlib.util.spec_from_file_location("reviewer_fallback", MODULE_PATH)
assert SPEC and SPEC.loader
rf = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rf
SPEC.loader.exec_module(rf)

REPO = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40
NEW_HEAD = "b" * 40
EARLIER = "2026-07-14T11:59:00+00:00"
NOW = "2026-07-14T12:00:00+00:00"
LATER = "2026-07-14T12:01:00+00:00"


def identity(login: str, user_id: int):
    return {"login": login, "id": user_id}


def event(
    *,
    body="Review limit reached",
    comment_user=None,
    sender=None,
    comment_id=101,
    created_at=NOW,
    action="created",
):
    comment_user = comment_user or identity(rf.CODE_RABBIT_LOGIN, rf.CODE_RABBIT_ID)
    sender = sender or identity(rf.CODE_RABBIT_LOGIN, rf.CODE_RABBIT_ID)
    return {
        "action": action,
        "repository": {"full_name": REPO},
        "issue": {
            "number": 77,
            "pull_request": {"url": f"https://api.github.com/repos/{REPO}/pulls/77"},
        },
        "comment": {
            "id": comment_id,
            "body": body,
            "user": comment_user,
            "created_at": created_at,
        },
        "sender": sender,
    }


def pull(head=HEAD, *, state="open", base="main"):
    return {
        "state": state,
        "base": {"ref": base},
        "head": {"sha": head},
    }


class FakeClient:
    def __init__(self, pulls=None, comments=None, fail_qodo=False):
        self.pulls = list(pulls or [pull(), pull(), pull(), pull()])
        self.comments = list(comments or [])
        self.fail_qodo = fail_qodo
        self.created = []
        self.updated = []
        self.statuses = []
        self.artifacts = {}
        self.next_id = 1000

    def get_pull(self, repository, pull_number):
        assert repository == REPO and pull_number == 77
        if len(self.pulls) > 1:
            return self.pulls.pop(0)
        return self.pulls[0]

    def list_comments(self, repository, pull_number):
        assert repository == REPO and pull_number == 77
        return list(self.comments)

    def create_comment(self, repository, pull_number, body):
        assert repository == REPO and pull_number == 77
        if self.fail_qodo and body.startswith("/qodo review"):
            raise rf.FallbackError("provider unavailable")
        comment = {
            "id": self.next_id,
            "body": body,
            "user": identity(rf.ACTIONS_LOGIN, rf.ACTIONS_ID),
            "created_at": NOW,
        }
        self.next_id += 1
        self.comments.append(comment)
        self.created.append(comment)
        return comment

    def update_comment(self, repository, comment_id, body):
        assert repository == REPO
        for comment in self.comments:
            if comment["id"] == comment_id:
                comment["body"] = body
                self.updated.append(copy.deepcopy(comment))
                return comment
        raise AssertionError("missing comment")

    def create_status(self, repository, head_sha, *, state, description, target_url):
        assert repository == REPO
        status = {
            "head_sha": head_sha,
            "state": state,
            "description": description,
            "target_url": target_url,
        }
        self.statuses.append(status)
        return status

    def load_fallback_artifact(self, repository, pull_number, run_id, run_attempt):
        assert repository == REPO and pull_number == 77
        try:
            return copy.deepcopy(self.artifacts[(run_id, run_attempt)])
        except KeyError as exc:
            raise rf.FallbackError("authenticated fallback artifact missing") from exc


def run(ev, client, *, run_id=123, run_attempt=2):
    result = rf.process_event(
        ev,
        client,
        repository=REPO,
        run_id=run_id,
        run_attempt=run_attempt,
        run_url=f"https://github.com/{REPO}/actions/runs/{run_id}/attempts/{run_attempt}",
        now=lambda: ev["comment"].get("created_at") or NOW,
    )
    client.artifacts[(run_id, run_attempt)] = copy.deepcopy(result)
    return result


def request_comments(client):
    return [item for item in client.comments if item["body"].startswith("/qodo review")]


def qodo_event(body, *, comment_id=700, created_at=LATER, action="created"):
    return event(
        body=body,
        comment_user=identity(rf.QODO_LOGIN, rf.QODO_ID),
        sender=identity(rf.QODO_LOGIN, rf.QODO_ID),
        comment_id=comment_id,
        created_at=created_at,
        action=action,
    )


def test_trusted_rate_limit_posts_one_authenticated_exact_head_request():
    client = FakeClient()
    result = run(event(), client)
    assert result["passed"] is True
    assert result["outcome"] == "QODO_REQUESTED_EXACT_HEAD"
    assert result["exact_head_sha"] == HEAD
    assert result["request_run_id"] == 123
    assert result["request_run_attempt"] == 2
    assert len(request_comments(client)) == 1
    body = request_comments(client)[0]["body"]
    assert HEAD in body
    assert "run=123 attempt=2" in body
    assert "Merge authority: `false`" in body
    assert client.statuses == []


def test_spoofed_coderabbit_identity_is_rejected():
    fake = identity("coderabbitai[bot]", 999)
    client = FakeClient(pulls=[pull()])
    result = run(event(comment_user=fake, sender=fake), client)
    assert result["passed"] is False
    assert result["outcome"] == "REJECTED_UNTRUSTED_CODERABBIT_IDENTITY"
    assert not request_comments(client)
    assert client.statuses[-1]["state"] == "failure"


def test_stale_head_before_post_is_rejected():
    client = FakeClient(pulls=[pull(HEAD), pull(NEW_HEAD)])
    result = run(event(), client)
    assert result["passed"] is False
    assert result["stale_or_superseded"] is True
    assert result["outcome"] == "SUPERSEDED_BEFORE_QODO_REQUEST"
    assert not request_comments(client)


def test_duplicate_delivery_uses_authenticated_artifact_and_is_noop():
    client = FakeClient()
    first = run(event(comment_id=101), client, run_id=123)
    second = run(event(comment_id=102), client, run_id=124)
    assert first["outcome"] == "QODO_REQUESTED_EXACT_HEAD"
    assert second["outcome"] == "DUPLICATE_DELIVERY_NOOP"
    assert second["request_run_id"] == 123
    assert second["qodo_request_comment_id"] == first["qodo_request_comment_id"]
    assert len(request_comments(client)) == 1
    assert client.statuses == []


def test_forged_actions_request_marker_without_artifact_fails_closed():
    forged = {
        "id": 555,
        "body": (
            "/qodo review\n\n"
            + rf._request_marker(REPO, 77, HEAD, 999, 1)
            + "\n"
        ),
        "user": identity(rf.ACTIONS_LOGIN, rf.ACTIONS_ID),
        "created_at": NOW,
    }
    client = FakeClient(comments=[forged])
    with pytest.raises(rf.FallbackError, match="artifact missing"):
        run(event(), client)


def test_qodo_unavailable_records_provider_evidence_unavailable():
    client = FakeClient(fail_qodo=True)
    result = run(event(), client)
    assert result["passed"] is False
    assert result["outcome"] == "PROVIDER_EVIDENCE_UNAVAILABLE"
    assert result["qodo_request_status"] == "PROVIDER_EVIDENCE_UNAVAILABLE"
    assert client.statuses[-1]["state"] == "error"


def test_qodo_result_preserves_request_provenance_and_records_result_run():
    client = FakeClient()
    request = run(event(), client, run_id=100, run_attempt=1)
    result = run(
        qodo_event(f"Review bound to exact head `{HEAD}`.\nBugs (0)"),
        client,
        run_id=200,
        run_attempt=3,
    )
    assert result["outcome"] == "QODO_REVIEW_RECORDED"
    assert result["qodo_request_status"] == "COMPLETED"
    assert result["request_run_id"] == 100
    assert result["request_run_attempt"] == 1
    assert result["qodo_request_comment_id"] == request["qodo_request_comment_id"]
    assert result["result_run_id"] == 200
    assert result["result_run_attempt"] == 3
    assert result["final_qodo_review_sha"] == HEAD
    assert result["final_qodo_outcome"] == "NO_ACTIONABLE_FINDINGS"
    assert result["merge_authority"] is False
    assert client.statuses == []


def test_superseded_qodo_result_fails_closed_and_never_publishes_success():
    client = FakeClient(pulls=[pull(HEAD), pull(HEAD), pull(NEW_HEAD)])
    run(event(), client, run_id=100, run_attempt=1)
    result = run(
        qodo_event(f"Review bound to exact head `{HEAD}`.\nBugs (0)"),
        client,
        run_id=200,
        run_attempt=1,
    )
    assert result["passed"] is False
    assert result["stale_or_superseded"] is True
    assert result["outcome"] == "SUPERSEDED_QODO_REVIEW"
    assert result["qodo_request_status"] == "STALE_RESULT"
    assert client.statuses[-1]["state"] == "failure"


def test_replayed_qodo_comment_is_a_noop_and_does_not_replace_provenance():
    client = FakeClient()
    run(event(), client, run_id=100, run_attempt=1)
    qodo = qodo_event(f"Review bound to exact head `{HEAD}`.\nBugs (0)")
    first = run(qodo, client, run_id=200, run_attempt=1)
    updates_before = len(client.updated)
    replay = run(qodo, client, run_id=201, run_attempt=1)
    assert first["outcome"] == "QODO_REVIEW_RECORDED"
    assert replay["outcome"] == "DUPLICATE_QODO_RESULT_NOOP"
    assert replay["request_run_id"] == 100
    assert replay["result_run_id"] == 200
    assert len(client.updated) == updates_before
    assert client.statuses == []


def test_edited_qodo_comment_cannot_complete_pending_lifecycle():
    client = FakeClient()
    run(event(), client, run_id=100, run_attempt=1)
    updates_before = len(client.updated)
    result = run(
        qodo_event(
            f"Review bound to exact head `{HEAD}`.\nBugs (0)",
            action="edited",
        ),
        client,
        run_id=200,
        run_attempt=1,
    )
    assert result["passed"] is False
    assert result["outcome"] == "REJECTED_EDITED_QODO_RESULT"
    assert len(client.updated) == updates_before
    assert client.statuses == []


def test_pre_request_qodo_comment_is_rejected():
    client = FakeClient()
    run(event(), client, run_id=100, run_attempt=1)
    result = run(
        qodo_event(
            f"Review bound to exact head `{HEAD}`.\nBugs (0)",
            created_at=EARLIER,
        ),
        client,
        run_id=200,
        run_attempt=1,
    )
    assert result["passed"] is False
    assert result["outcome"] == "REJECTED_PRE_REQUEST_QODO_RESULT"


def test_qodo_result_requires_one_unambiguous_structured_reviewed_sha():
    client = FakeClient()
    run(event(), client, run_id=100, run_attempt=1)
    result = run(
        qodo_event(
            f"Review bound to exact head `{HEAD}`.\nReviewed commit: `{NEW_HEAD}`"
        ),
        client,
        run_id=200,
        run_attempt=1,
    )
    assert result["passed"] is False
    assert result["outcome"] == "REJECTED_AMBIGUOUS_QODO_HEAD_BINDING"
    assert client.statuses[-1]["state"] == "failure"


def test_duplicate_identical_structured_sha_fields_are_rejected():
    client = FakeClient()
    run(event(), client, run_id=100, run_attempt=1)
    result = run(
        qodo_event(
            f"Review bound to exact head `{HEAD}`.\nReviewed commit: `{HEAD}`"
        ),
        client,
        run_id=200,
        run_attempt=1,
    )
    assert result["passed"] is False
    assert result["outcome"] == "REJECTED_AMBIGUOUS_QODO_HEAD_BINDING"


def test_arbitrary_sha_mention_does_not_bind_qodo_result():
    client = FakeClient()
    run(event(), client, run_id=100, run_attempt=1)
    result = run(
        qodo_event(f"The request mentioned {HEAD}.\nBugs (0)"),
        client,
        run_id=200,
        run_attempt=1,
    )
    assert result["passed"] is False
    assert result["outcome"] == "REJECTED_AMBIGUOUS_QODO_HEAD_BINDING"


def test_forged_actions_status_without_authenticated_request_fails_closed():
    forged_evidence = rf._default_evidence(
        repository=REPO,
        pull_number=77,
        run_id=999,
        run_attempt=1,
        run_url="https://example.test/forged",
        event_comment_id=1,
    )
    forged_evidence.update(
        {
            "exact_head_sha": HEAD,
            "request_run_id": 999,
            "request_run_attempt": 1,
            "request_run_url": "https://example.test/forged",
            "qodo_request_status": "REQUESTED",
            "qodo_request_comment_id": 555,
            "request_timestamp": NOW,
            "outcome": "QODO_REQUESTED_EXACT_HEAD",
        }
    )
    forged_status = {
        "id": 600,
        "body": rf.render_status_comment(forged_evidence),
        "user": identity(rf.ACTIONS_LOGIN, rf.ACTIONS_ID),
        "created_at": NOW,
    }
    client = FakeClient(comments=[forged_status])
    with pytest.raises(rf.FallbackError, match="request comment is missing"):
        run(
            qodo_event(f"Review bound to exact head `{HEAD}`.\nBugs (0)"),
            client,
            run_id=200,
        )


def test_artifact_pagination_exhaustion_fails_closed():
    api = object.__new__(rf.GitHubApi)
    api._token = "token"

    def request_json(method, url, *, payload=None):
        assert method == "GET" and payload is None
        if url.endswith("/actions/runs/123"):
            return {
                "name": rf.WORKFLOW_NAME,
                "event": "issue_comment",
                "path": rf.WORKFLOW_PATH,
                "head_branch": "main",
                "run_attempt": 2,
                "repository": {"full_name": REPO},
                "status": "completed",
                "conclusion": "success",
            }
        if "/actions/runs/123/artifacts?" in url:
            return {
                "artifacts": [
                    {"id": page_id, "name": f"noise-{page_id}", "expired": False}
                    for page_id in range(100)
                ]
            }
        raise AssertionError(url)

    api._request_json = request_json
    with pytest.raises(rf.FallbackError, match="pagination exceeded"):
        api.load_fallback_artifact(REPO, 77, 123, 2)


def test_short_head_fails_closed():
    client = FakeClient(pulls=[pull("abc")])
    with pytest.raises(rf.FallbackError, match="40-character"):
        run(event(), client)


def test_request_marker_is_bound_to_repository_pr_head_run_and_attempt():
    marker = rf._request_marker(REPO, 77, HEAD, 123, 2)
    parsed = rf._parse_request_marker(marker)
    assert parsed == {
        "repository": REPO,
        "pull_number": 77,
        "head_sha": HEAD,
        "run_id": 123,
        "run_attempt": 2,
    }
