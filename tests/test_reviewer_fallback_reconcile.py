from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / ".github/trust-root/scripts/reviewer_fallback_runtime.py"
SPEC = importlib.util.spec_from_file_location("reviewer_fallback_runtime_tests", MODULE_PATH)
assert SPEC and SPEC.loader
runtime = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime
SPEC.loader.exec_module(runtime)

rec = runtime.rec
rf = runtime.rf
REPO = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40
OLD_HEAD = "b" * 40
NOW = "2026-07-17T00:00:00+00:00"


def identity(login: str, user_id: int) -> dict[str, object]:
    return {"login": login, "id": user_id}


def coderabbit_comment(
    *,
    comment_id: int = 101,
    head_sha: str = HEAD,
    user_id: int = rf.CODE_RABBIT_ID,
) -> dict[str, object]:
    return {
        "id": comment_id,
        "body": (
            "Review limit reached\n"
            "We couldn't start this review.\n"
            f"Reviewing commits between `{OLD_HEAD}` and `{head_sha}`."
        ),
        "user": identity(rf.CODE_RABBIT_LOGIN, user_id),
        "created_at": NOW,
    }


class FakeClient:
    def __init__(self) -> None:
        self.pull = {
            "number": 77,
            "url": f"https://api.github.com/repos/{REPO}/pulls/77",
            "state": "open",
            "base": {"ref": "main"},
            "head": {"sha": HEAD},
        }
        self.comments: list[dict[str, object]] = [coderabbit_comment()]
        self.created: list[dict[str, object]] = []
        self.updated: list[dict[str, object]] = []
        self.statuses: list[dict[str, object]] = []
        self.dispatches: list[dict[str, object]] = []
        self.artifacts: dict[tuple[int, int], dict[str, object]] = {}
        self.next_id = 1000

    def list_open_pulls(self, repository: str):
        assert repository == REPO
        return [copy.deepcopy(self.pull)]

    def get_pull(self, repository: str, pull_number: int):
        assert repository == REPO and pull_number == 77
        return copy.deepcopy(self.pull)

    def list_comments(self, repository: str, pull_number: int):
        assert repository == REPO and pull_number == 77
        return copy.deepcopy(self.comments)

    def dispatch_reconciliation(
        self,
        repository: str,
        *,
        pull_number: int,
        comment_id: int,
        ref: str,
    ) -> None:
        assert repository == REPO
        self.dispatches.append(
            {
                "pull_number": pull_number,
                "comment_id": comment_id,
                "ref": ref,
            }
        )

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
        return copy.deepcopy(comment)

    def update_comment(self, repository: str, comment_id: int, body: str):
        assert repository == REPO
        for comment in self.comments:
            if comment["id"] == comment_id:
                comment["body"] = body
                self.updated.append(copy.deepcopy(comment))
                return copy.deepcopy(comment)
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


def test_discovery_dispatches_only_canonical_current_head_comment() -> None:
    client = FakeClient()

    result = rec.discover(
        client,
        repository=REPO,
        run_id=10,
        run_attempt=1,
        run_url="https://example.invalid/runs/10/attempts/1",
        ref="main",
    )

    assert result["outcome"] == "RECONCILIATION_DISPATCHED"
    assert result["selected_head_sha"] == HEAD
    assert result["selected_coderabbit_comment_id"] == 101
    assert client.dispatches == [
        {"pull_number": 77, "comment_id": 101, "ref": "main"}
    ]
    assert result["merge_authority"] is False


def test_discovery_ignores_comment_bound_to_superseded_head() -> None:
    client = FakeClient()
    client.comments = [coderabbit_comment(head_sha=OLD_HEAD)]

    result = rec.discover(
        client,
        repository=REPO,
        run_id=10,
        run_attempt=1,
        run_url="https://example.invalid/runs/10/attempts/1",
        ref="main",
    )

    assert result["outcome"] == "DISCOVERY_NOOP"
    assert client.dispatches == []


def test_discovery_ignores_spoofed_numeric_identity() -> None:
    client = FakeClient()
    client.comments = [coderabbit_comment(user_id=999)]

    result = rec.discover(
        client,
        repository=REPO,
        run_id=10,
        run_attempt=1,
        run_url="https://example.invalid/runs/10/attempts/1",
        ref="main",
    )

    assert result["outcome"] == "DISCOVERY_NOOP"
    assert client.dispatches == []


def test_reconcile_requests_exact_head_once_and_replay_is_noop() -> None:
    client = FakeClient()

    first = rec.reconcile(
        client,
        repository=REPO,
        pull_number=77,
        comment_id=101,
        run_id=20,
        run_attempt=1,
        run_url="https://example.invalid/runs/20/attempts/1",
    )
    client.artifacts[(20, 1)] = copy.deepcopy(first)

    second = rec.reconcile(
        client,
        repository=REPO,
        pull_number=77,
        comment_id=101,
        run_id=21,
        run_attempt=1,
        run_url="https://example.invalid/runs/21/attempts/1",
    )

    requests = [
        comment
        for comment in client.comments
        if str(comment["body"]).startswith("/qodo review")
    ]
    assert first["outcome"] == "QODO_REQUESTED_EXACT_HEAD"
    assert second["outcome"] == "DUPLICATE_DELIVERY_NOOP"
    assert len(requests) == 1
    assert HEAD in str(requests[0]["body"])
    assert client.statuses == []


def test_reconcile_rejects_stale_comment_and_publishes_only_failure() -> None:
    client = FakeClient()
    client.comments = [coderabbit_comment(head_sha=OLD_HEAD)]

    result = rec.reconcile(
        client,
        repository=REPO,
        pull_number=77,
        comment_id=101,
        run_id=20,
        run_attempt=1,
        run_url="https://example.invalid/runs/20/attempts/1",
    )

    assert result["outcome"] == "RECONCILE_REJECTED_UNTRUSTED_OR_STALE_COMMENT"
    assert result["passed"] is False
    assert result["merge_authority"] is False
    assert client.created == []
    assert [status["state"] for status in client.statuses] == ["failure"]


def test_runtime_accepts_dispatch_artifacts_but_not_schedule_artifacts() -> None:
    assert "workflow_dispatch" in runtime.ALLOWED_ARTIFACT_RUN_EVENTS
    assert "schedule" not in runtime.ALLOWED_ARTIFACT_RUN_EVENTS
    assert set(rf.SUPPORTED_EVENT_NAMES).issubset(
        runtime.ALLOWED_ARTIFACT_RUN_EVENTS
    )
