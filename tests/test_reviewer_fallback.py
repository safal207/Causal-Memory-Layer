from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / ".github/trust-root/scripts/reviewer_fallback.py"
SPEC = importlib.util.spec_from_file_location("reviewer_fallback", MODULE_PATH)
assert SPEC and SPEC.loader
rf = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rf
SPEC.loader.exec_module(rf)

REPO = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40
NEW_HEAD = "b" * 40
NOW = "2026-07-14T12:00:00+00:00"


def identity(login: str, user_id: int):
    return {"login": login, "id": user_id}


def event(
    *,
    body="Review limit reached",
    comment_user=None,
    sender=None,
    comment_id=101,
):
    comment_user = comment_user or identity(rf.CODE_RABBIT_LOGIN, rf.CODE_RABBIT_ID)
    sender = sender or identity(rf.CODE_RABBIT_LOGIN, rf.CODE_RABBIT_ID)
    return {
        "repository": {"full_name": REPO},
        "issue": {
            "number": 77,
            "pull_request": {"url": f"https://api.github.com/repos/{REPO}/pulls/77"},
        },
        "comment": {
            "id": comment_id,
            "body": body,
            "user": comment_user,
            "created_at": NOW,
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
        self.pulls = list(pulls or [pull(), pull()])
        self.comments = list(comments or [])
        self.fail_qodo = fail_qodo
        self.created = []
        self.updated = []
        self.statuses = []
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
                self.updated.append(comment)
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


def run(ev, client):
    return rf.process_event(
        ev,
        client,
        repository=REPO,
        run_id=123,
        run_attempt=2,
        run_url="https://github.com/safal207/Causal-Memory-Layer/actions/runs/123/attempts/2",
        now=lambda: NOW,
    )


def request_comments(client):
    return [item for item in client.comments if item["body"].startswith("/qodo review")]


def test_trusted_rate_limit_posts_one_exact_head_qodo_request():
    client = FakeClient()
    result = run(event(), client)
    assert result["passed"] is True
    assert result["outcome"] == "QODO_REQUESTED_EXACT_HEAD"
    assert result["exact_head_sha"] == HEAD
    assert result["qodo_request_status"] == "REQUESTED"
    assert len(request_comments(client)) == 1
    assert HEAD in request_comments(client)[0]["body"]
    assert "Merge authority: `false`" in request_comments(client)[0]["body"]
    assert client.statuses[-1]["state"] == "success"


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


def test_duplicate_delivery_is_noop():
    marker = rf._request_marker(REPO, 77, HEAD)
    existing = {
        "id": 555,
        "body": f"/qodo review\n\n{marker}\n",
        "user": identity(rf.ACTIONS_LOGIN, rf.ACTIONS_ID),
        "created_at": NOW,
    }
    client = FakeClient(pulls=[pull()], comments=[existing])
    result = run(event(), client)
    assert result["passed"] is True
    assert result["outcome"] == "DUPLICATE_DELIVERY_NOOP"
    assert result["qodo_request_comment_id"] == 555
    assert len(request_comments(client)) == 1


def test_concurrent_serialized_deliveries_create_only_one_request():
    client = FakeClient(pulls=[pull(), pull(), pull()])
    first = run(event(comment_id=101), client)
    second = run(event(comment_id=102), client)
    assert first["outcome"] == "QODO_REQUESTED_EXACT_HEAD"
    assert second["outcome"] == "DUPLICATE_DELIVERY_NOOP"
    assert len(request_comments(client)) == 1


def test_qodo_unavailable_records_provider_evidence_unavailable():
    client = FakeClient(fail_qodo=True)
    result = run(event(), client)
    assert result["passed"] is False
    assert result["outcome"] == "PROVIDER_EVIDENCE_UNAVAILABLE"
    assert result["qodo_request_status"] == "PROVIDER_EVIDENCE_UNAVAILABLE"
    assert client.statuses[-1]["state"] == "error"


def test_qodo_result_updates_canonical_status_for_exact_head():
    base_evidence = rf._default_evidence(
        repository=REPO,
        pull_number=77,
        run_id=100,
        run_attempt=1,
        run_url="https://example.test/old",
        event_comment_id=99,
    )
    base_evidence.update(
        {
            "exact_head_sha": HEAD,
            "coderabbit_status": "RATE_LIMITED",
            "qodo_request_status": "REQUESTED",
            "qodo_request_comment_id": 500,
            "request_timestamp": NOW,
            "outcome": "QODO_REQUESTED_EXACT_HEAD",
        }
    )
    status_comment = {
        "id": 600,
        "body": rf.render_status_comment(base_evidence),
        "user": identity(rf.ACTIONS_LOGIN, rf.ACTIONS_ID),
        "created_at": NOW,
    }
    qodo_event = event(
        body=f"Code Review by Qodo\nBugs (0)\nReviewed commit {HEAD}",
        comment_user=identity(rf.QODO_LOGIN, rf.QODO_ID),
        sender=identity(rf.QODO_LOGIN, rf.QODO_ID),
        comment_id=700,
    )
    client = FakeClient(pulls=[pull()], comments=[status_comment])
    result = run(qodo_event, client)
    assert result["outcome"] == "QODO_REVIEW_RECORDED"
    assert result["qodo_request_status"] == "COMPLETED"
    assert result["final_qodo_review_sha"] == HEAD
    assert result["final_qodo_outcome"] == "NO_ACTIONABLE_FINDINGS"
    assert result["merge_authority"] is False
    assert client.updated


def test_qodo_result_without_exact_sha_is_ignored():
    base_evidence = rf._default_evidence(
        repository=REPO,
        pull_number=77,
        run_id=100,
        run_attempt=1,
        run_url="https://example.test/old",
        event_comment_id=99,
    )
    base_evidence["exact_head_sha"] = HEAD
    status_comment = {
        "id": 600,
        "body": rf.render_status_comment(base_evidence),
        "user": identity(rf.ACTIONS_LOGIN, rf.ACTIONS_ID),
        "created_at": NOW,
    }
    qodo_event = event(
        body="Code Review by Qodo\nBugs (0)",
        comment_user=identity(rf.QODO_LOGIN, rf.QODO_ID),
        sender=identity(rf.QODO_LOGIN, rf.QODO_ID),
        comment_id=700,
    )
    client = FakeClient(comments=[status_comment])
    result = run(qodo_event, client)
    assert result["outcome"] == "IGNORED_QODO_RESULT_WITHOUT_EXACT_HEAD_BINDING"
    assert not client.updated


def test_short_head_fails_closed():
    client = FakeClient(pulls=[pull("abc")])
    with pytest.raises(rf.FallbackError, match="40-character"):
        run(event(), client)
