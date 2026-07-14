from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / ".github/trust-root/scripts/reviewer_fallback.py"
SPEC = importlib.util.spec_from_file_location("reviewer_fallback_untrusted", CORE_PATH)
assert SPEC and SPEC.loader
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
SPEC.loader.exec_module(core)

REPO = "safal207/Causal-Memory-Layer"
HEAD = "a" * 40


def identity(login: str, user_id: int):
    return {"login": login, "id": user_id}


class NoCallClient:
    def __getattr__(self, name):
        raise AssertionError(f"untrusted input must not call client.{name}")


class MissingArtifactClient:
    def load_fallback_artifact(self, *args, **kwargs):
        raise core.FallbackError("authenticated artifact missing")


def untrusted_marker_event(*, body="Review limit reached"):
    return {
        "action": "created",
        "repository": {"full_name": REPO},
        "issue": {
            "number": 77,
            "pull_request": {"url": "https://example.test/pr/77"},
        },
        "comment": {
            "id": 101,
            "body": body,
            "created_at": "2026-07-14T12:00:00+00:00",
            "user": identity("attacker", 999),
        },
        "sender": identity("attacker", 999),
    }


def test_untrusted_rate_limit_marker_is_ignored_without_any_write_capable_calls():
    result = core.process_event(
        untrusted_marker_event(),
        NoCallClient(),
        repository=REPO,
        run_id=123,
        run_attempt=1,
        run_url="https://example.test/run/123/attempt/1",
    )
    assert result["passed"] is True
    assert result["outcome"] == "IGNORED_UNRELATED_COMMENT"
    assert result["qodo_request_status"] == "NOT_REQUESTED"
    assert result["merge_authority"] is False


def test_sender_author_disagreement_is_ignored_before_handler():
    event = untrusted_marker_event()
    event["comment"]["user"] = identity(core.CODE_RABBIT_LOGIN, core.CODE_RABBIT_ID)
    event["sender"] = identity("attacker", 999)
    result = core.process_event(
        event,
        NoCallClient(),
        repository=REPO,
        run_id=123,
        run_attempt=1,
        run_url="https://example.test/run/123/attempt/1",
    )
    assert result["passed"] is True
    assert result["outcome"] == "IGNORED_UNRELATED_COMMENT"


def test_untrusted_malformed_request_marker_is_skipped_before_parsing():
    comments = [
        {
            "id": 555,
            "body": "<!-- cml-qodo-fallback-request:v2 malformed -->",
            "user": identity("attacker", 999),
            "created_at": "2026-07-14T12:00:00+00:00",
        }
    ]
    assert (
        core._find_request_comment(
            NoCallClient(),
            comments,
            repository=REPO,
            pull_number=77,
            head_sha=HEAD,
        )
        is None
    )


def test_trusted_actions_malformed_request_marker_is_skipped_resiliently():
    comments = [
        {
            "id": 555,
            "body": "<!-- cml-qodo-fallback-request:v2 malformed -->",
            "user": identity(core.ACTIONS_LOGIN, core.ACTIONS_ID),
            "created_at": "2026-07-14T12:00:00+00:00",
        }
    ]
    assert (
        core._find_request_comment(
            NoCallClient(),
            comments,
            repository=REPO,
            pull_number=77,
            head_sha=HEAD,
        )
        is None
    )


def test_syntactically_valid_but_unauthenticated_actions_marker_is_skipped():
    comments = [
        {
            "id": 555,
            "body": "/qodo review\n\n"
            + core._request_marker(REPO, 77, HEAD, 999, 1)
            + "\n",
            "user": identity(core.ACTIONS_LOGIN, core.ACTIONS_ID),
            "created_at": "2026-07-14T12:00:00+00:00",
        }
    ]
    assert (
        core._find_request_comment(
            MissingArtifactClient(),
            comments,
            repository=REPO,
            pull_number=77,
            head_sha=HEAD,
        )
        is None
    )
