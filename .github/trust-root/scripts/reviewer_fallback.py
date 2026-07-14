#!/usr/bin/env python3
"""Trusted CodeRabbit rate-limit fallback to exact-head Qodo review."""

from __future__ import annotations

import argparse
import json
import os
import re
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = "cml-reviewer-fallback-v1"
STATUS_MARKER = "<!-- cml-reviewer-fallback-status:v1 -->"
REQUEST_MARKER_PREFIX = "<!-- cml-qodo-fallback-request:v1"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
FULL_SHA_PATTERN = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{40})(?![0-9a-fA-F])")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
CODE_RABBIT_LOGIN = "coderabbitai[bot]"
CODE_RABBIT_ID = 136622811
QODO_LOGIN = "qodo-code-review[bot]"
QODO_ID = 151058649
ACTIONS_LOGIN = "github-actions[bot]"
ACTIONS_ID = 41898282
RATE_LIMIT_MARKERS = (
    "Review limit reached",
    "review rate limit",
    "couldn't start this review",
)


class FallbackError(RuntimeError):
    """A trusted reviewer fallback decision could not be completed safely."""


@dataclass(frozen=True)
class Identity:
    login: str
    user_id: int


def _identity(payload: object) -> Identity:
    if not isinstance(payload, dict):
        raise FallbackError("identity payload must be an object")
    login = payload.get("login")
    user_id = payload.get("id")
    if not isinstance(login, str) or not isinstance(user_id, int):
        raise FallbackError("identity payload is incomplete")
    return Identity(login=login, user_id=user_id)


def _matches_identity(payload: object, *, login: str, user_id: int) -> bool:
    try:
        observed = _identity(payload)
    except FallbackError:
        return False
    return observed.login == login and observed.user_id == user_id


def _normalize_repository(value: object) -> str:
    if not isinstance(value, str):
        raise FallbackError("repository must be text")
    result = value.strip()
    if not REPOSITORY_PATTERN.fullmatch(result):
        raise FallbackError("repository must use owner/name form")
    return result


def _normalize_sha(value: object) -> str:
    if not isinstance(value, str):
        raise FallbackError("head SHA must be text")
    result = value.strip().lower()
    if not SHA_PATTERN.fullmatch(result):
        raise FallbackError("head SHA must be a full 40-character hexadecimal SHA")
    return result


def _positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool):
        raise FallbackError(f"{label} must be a positive integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise FallbackError(f"{label} must be a positive integer") from exc
    if result < 1:
        raise FallbackError(f"{label} must be a positive integer")
    return result


def _printable_comment_body(value: object) -> str:
    if not isinstance(value, str):
        raise FallbackError("comment body must be text")
    normalized = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(char) in {"Cs"} for char in normalized):
        raise FallbackError("comment body contains invalid Unicode")
    return normalized


def _rate_limit_marker_present(body: str) -> bool:
    folded = body.casefold()
    return any(marker.casefold() in folded for marker in RATE_LIMIT_MARKERS)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _default_evidence(
    *,
    repository: str,
    pull_number: int | None,
    run_id: int,
    run_attempt: int,
    run_url: str,
    event_comment_id: int | None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "pull_number": pull_number,
        "exact_head_sha": None,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "run_url": run_url,
        "event_comment_id": event_comment_id,
        "coderabbit_status": "NOT_APPLICABLE",
        "coderabbit_comment_id": None,
        "qodo_request_status": "NOT_REQUESTED",
        "qodo_request_comment_id": None,
        "request_timestamp": None,
        "stale_or_superseded": False,
        "final_qodo_review_identity": None,
        "final_qodo_review_comment_id": None,
        "final_qodo_review_sha": None,
        "final_qodo_outcome": None,
        "outcome": "IGNORED",
        "passed": True,
        "merge_authority": False,
    }


def _request_marker(repository: str, pull_number: int, head_sha: str) -> str:
    return (
        f"{REQUEST_MARKER_PREFIX} repository={repository} "
        f"pr={pull_number} head={head_sha} -->"
    )


def build_qodo_request(repository: str, pull_number: int, head_sha: str) -> str:
    repository = _normalize_repository(repository)
    pull_number = _positive_int(pull_number, label="pull number")
    head_sha = _normalize_sha(head_sha)
    return f"""/qodo review

{_request_marker(repository, pull_number, head_sha)}

Exact head: `{head_sha}`

Requested reviewer: CodeRabbit
Execution provider: Qodo
Evidence kind: proxy review
Fallback reason: `RATE_LIMITED`
Merge authority: `false`

Review the complete diff bound to the exact head above. Reconstruct intended invariants first and treat green CI as evidence, not proof. Search specifically for fail-open behavior, stale-SHA acceptance, artifact substitution, symlink or path ambiguity, duplicate-key ambiguity, mutable-reference downgrade, cross-run evidence mixing, nondeterminism, unsafe error handling, and reviewer-identity confusion.

For every actionable finding include severity, affected guarantee, exact boundary, concrete failure path, minimal regression test, and minimal remediation. Do not report cosmetic advice. If no actionable findings remain, state that explicitly and bind the conclusion to `{head_sha}`.

Execute this rubric, but never claim to be CodeRabbit. Proxy evidence is not native approval and grants no merge authority.
"""


def render_status_comment(evidence: dict[str, Any]) -> str:
    payload = json.dumps(evidence, indent=2, sort_keys=True)
    return f"{STATUS_MARKER}\n\n```json\n{payload}\n```\n"


def parse_status_comment(body: object) -> dict[str, Any]:
    text = _printable_comment_body(body)
    if STATUS_MARKER not in text:
        raise FallbackError("status marker is missing")
    match = re.search(r"```json\s*(\{.*\})\s*```", text, flags=re.DOTALL)
    if not match:
        raise FallbackError("status JSON block is missing")
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise FallbackError("status JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise FallbackError("status JSON must be an object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise FallbackError("status JSON schema is unsupported")
    return payload


def _comment_id(comment: dict[str, Any]) -> int:
    return _positive_int(comment.get("id"), label="comment id")


def _trusted_actions_comment(comment: dict[str, Any]) -> bool:
    return _matches_identity(
        comment.get("user"), login=ACTIONS_LOGIN, user_id=ACTIONS_ID
    )


def _find_status_comment(comments: list[dict[str, Any]]) -> dict[str, Any] | None:
    matches = [
        comment
        for comment in comments
        if _trusted_actions_comment(comment)
        and STATUS_MARKER in str(comment.get("body", ""))
    ]
    if len(matches) > 1:
        raise FallbackError("multiple canonical reviewer-fallback status comments")
    return matches[0] if matches else None


def _find_request_comment(
    comments: list[dict[str, Any]],
    *,
    repository: str,
    pull_number: int,
    head_sha: str,
) -> dict[str, Any] | None:
    marker = _request_marker(repository, pull_number, head_sha)
    matches = [
        comment
        for comment in comments
        if _trusted_actions_comment(comment) and marker in str(comment.get("body", ""))
    ]
    if len(matches) > 1:
        raise FallbackError("multiple Qodo fallback requests exist for the exact head")
    return matches[0] if matches else None


def _classify_qodo_outcome(body: str) -> str:
    folded = body.casefold()
    zero_bug_markers = (
        "bugs (0)",
        "no actionable findings",
        "didn't find any major issues",
        "did not find any major issues",
    )
    action_markers = (
        "action_required",
        "action required",
        "bugs (1)",
        "bugs (2)",
        "bugs (3)",
        "bugs (4)",
        "bugs (5)",
        "request changes",
    )
    if any(marker in folded for marker in zero_bug_markers):
        return "NO_ACTIONABLE_FINDINGS"
    if any(marker in folded for marker in action_markers):
        return "ACTIONABLE_FINDINGS"
    return "REVIEW_RECEIVED"


class GitHubApi:
    """Minimal GitHub REST client used by the trusted default-branch workflow."""

    def __init__(self, token: str):
        if not token:
            raise FallbackError("GITHUB_TOKEN is required")
        self._token = token

    def _request(
        self,
        method: str,
        url: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> tuple[Any, dict[str, str]]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "cml-reviewer-fallback",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read()
                decoded = json.loads(body) if body else None
                headers = {key.lower(): value for key, value in response.headers.items()}
                return decoded, headers
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise FallbackError(
                f"GitHub API {method} {url} failed: HTTP {exc.code}: {detail[:500]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise FallbackError(f"GitHub API {method} {url} failed: {exc}") from exc

    def get_pull(self, repository: str, pull_number: int) -> dict[str, Any]:
        payload, _ = self._request(
            "GET", f"https://api.github.com/repos/{repository}/pulls/{pull_number}"
        )
        if not isinstance(payload, dict):
            raise FallbackError("pull request response is invalid")
        return payload

    def list_comments(self, repository: str, pull_number: int) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        for page in range(1, 101):
            payload, _ = self._request(
                "GET",
                f"https://api.github.com/repos/{repository}/issues/{pull_number}/comments"
                f"?per_page=100&page={page}",
            )
            if not isinstance(payload, list) or not all(
                isinstance(item, dict) for item in payload
            ):
                raise FallbackError("issue comments response is invalid")
            comments.extend(payload)
            if len(payload) < 100:
                return comments
        raise FallbackError("issue comment pagination exceeded the safe bound")

    def create_comment(
        self, repository: str, pull_number: int, body: str
    ) -> dict[str, Any]:
        payload, _ = self._request(
            "POST",
            f"https://api.github.com/repos/{repository}/issues/{pull_number}/comments",
            payload={"body": body},
        )
        if not isinstance(payload, dict):
            raise FallbackError("created comment response is invalid")
        return payload

    def update_comment(
        self, repository: str, comment_id: int, body: str
    ) -> dict[str, Any]:
        payload, _ = self._request(
            "PATCH",
            f"https://api.github.com/repos/{repository}/issues/comments/{comment_id}",
            payload={"body": body},
        )
        if not isinstance(payload, dict):
            raise FallbackError("updated comment response is invalid")
        return payload

    def create_status(
        self,
        repository: str,
        head_sha: str,
        *,
        state: str,
        description: str,
        target_url: str,
    ) -> dict[str, Any]:
        payload, _ = self._request(
            "POST",
            f"https://api.github.com/repos/{repository}/statuses/{head_sha}",
            payload={
                "state": state,
                "context": "CML Reviewer Fallback",
                "description": description[:140],
                "target_url": target_url,
            },
        )
        if not isinstance(payload, dict):
            raise FallbackError("created status response is invalid")
        return payload


def _pull_snapshot(pull: dict[str, Any]) -> tuple[str, str, str]:
    state = pull.get("state")
    base = pull.get("base")
    head = pull.get("head")
    if not isinstance(state, str) or not isinstance(base, dict) or not isinstance(head, dict):
        raise FallbackError("pull request payload is incomplete")
    base_ref = base.get("ref")
    head_sha = head.get("sha")
    if not isinstance(base_ref, str):
        raise FallbackError("pull request base ref is missing")
    return state, base_ref, _normalize_sha(head_sha)


def _publish_status_comment(
    client: Any,
    *,
    repository: str,
    pull_number: int,
    comments: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    body = render_status_comment(evidence)
    existing = _find_status_comment(comments)
    if existing is None:
        return client.create_comment(repository, pull_number, body)
    return client.update_comment(repository, _comment_id(existing), body)


def _publish_commit_status(
    client: Any,
    *,
    repository: str,
    head_sha: str | None,
    evidence: dict[str, Any],
) -> None:
    if head_sha is None:
        return
    outcome = evidence["outcome"]
    if evidence.get("passed") is True:
        state = "success"
        description = f"Fallback evidence recorded: {outcome}"
    elif outcome == "PROVIDER_EVIDENCE_UNAVAILABLE":
        state = "error"
        description = "Qodo fallback evidence unavailable; never approval"
    else:
        state = "failure"
        description = f"Reviewer fallback rejected: {outcome}"
    client.create_status(
        repository,
        head_sha,
        state=state,
        description=description,
        target_url=evidence["run_url"],
    )


def _handle_coderabbit(
    event: dict[str, Any],
    client: Any,
    evidence: dict[str, Any],
    *,
    repository: str,
    pull_number: int,
    now: Callable[[], str],
) -> dict[str, Any]:
    comment = event["comment"]
    sender = event.get("sender")
    body = _printable_comment_body(comment.get("body"))

    evidence["coderabbit_comment_id"] = _comment_id(comment)
    if not _rate_limit_marker_present(body):
        evidence["outcome"] = "IGNORED_NON_RATE_LIMIT"
        return evidence

    if not _matches_identity(
        comment.get("user"), login=CODE_RABBIT_LOGIN, user_id=CODE_RABBIT_ID
    ) or not _matches_identity(
        sender, login=CODE_RABBIT_LOGIN, user_id=CODE_RABBIT_ID
    ):
        evidence.update(
            {
                "coderabbit_status": "SPOOFED_OR_UNTRUSTED",
                "outcome": "REJECTED_UNTRUSTED_CODERABBIT_IDENTITY",
                "passed": False,
            }
        )
        pull = client.get_pull(repository, pull_number)
        _, _, head_sha = _pull_snapshot(pull)
        evidence["exact_head_sha"] = head_sha
        comments = client.list_comments(repository, pull_number)
        _publish_status_comment(
            client,
            repository=repository,
            pull_number=pull_number,
            comments=comments,
            evidence=evidence,
        )
        _publish_commit_status(
            client, repository=repository, head_sha=head_sha, evidence=evidence
        )
        return evidence

    evidence["coderabbit_status"] = "RATE_LIMITED"
    pull = client.get_pull(repository, pull_number)
    state, base_ref, head_sha = _pull_snapshot(pull)
    evidence["exact_head_sha"] = head_sha
    if state != "open":
        evidence.update(
            {
                "outcome": "REJECTED_PULL_REQUEST_NOT_OPEN",
                "passed": False,
            }
        )
        return evidence
    if base_ref != "main":
        evidence.update(
            {
                "outcome": "REJECTED_UNEXPECTED_BASE",
                "passed": False,
            }
        )
        return evidence

    comments = client.list_comments(repository, pull_number)
    existing_request = _find_request_comment(
        comments,
        repository=repository,
        pull_number=pull_number,
        head_sha=head_sha,
    )
    if existing_request is not None:
        evidence.update(
            {
                "qodo_request_status": "EXISTING_EXACT_HEAD_REQUEST",
                "qodo_request_comment_id": _comment_id(existing_request),
                "request_timestamp": existing_request.get("created_at"),
                "outcome": "DUPLICATE_DELIVERY_NOOP",
                "passed": True,
            }
        )
        _publish_status_comment(
            client,
            repository=repository,
            pull_number=pull_number,
            comments=comments,
            evidence=evidence,
        )
        _publish_commit_status(
            client, repository=repository, head_sha=head_sha, evidence=evidence
        )
        return evidence

    latest_pull = client.get_pull(repository, pull_number)
    latest_state, latest_base, latest_head = _pull_snapshot(latest_pull)
    if latest_state != "open" or latest_base != "main" or latest_head != head_sha:
        evidence.update(
            {
                "stale_or_superseded": True,
                "outcome": "SUPERSEDED_BEFORE_QODO_REQUEST",
                "passed": False,
            }
        )
        _publish_status_comment(
            client,
            repository=repository,
            pull_number=pull_number,
            comments=comments,
            evidence=evidence,
        )
        _publish_commit_status(
            client, repository=repository, head_sha=head_sha, evidence=evidence
        )
        return evidence

    try:
        request_comment = client.create_comment(
            repository,
            pull_number,
            build_qodo_request(repository, pull_number, head_sha),
        )
    except Exception as exc:
        evidence.update(
            {
                "qodo_request_status": "PROVIDER_EVIDENCE_UNAVAILABLE",
                "outcome": "PROVIDER_EVIDENCE_UNAVAILABLE",
                "passed": False,
                "error": {"type": type(exc).__name__, "message": str(exc)},
            }
        )
        comments = client.list_comments(repository, pull_number)
        _publish_status_comment(
            client,
            repository=repository,
            pull_number=pull_number,
            comments=comments,
            evidence=evidence,
        )
        _publish_commit_status(
            client, repository=repository, head_sha=head_sha, evidence=evidence
        )
        return evidence

    evidence.update(
        {
            "qodo_request_status": "REQUESTED",
            "qodo_request_comment_id": _comment_id(request_comment),
            "request_timestamp": request_comment.get("created_at") or now(),
            "outcome": "QODO_REQUESTED_EXACT_HEAD",
            "passed": True,
        }
    )
    comments = client.list_comments(repository, pull_number)
    _publish_status_comment(
        client,
        repository=repository,
        pull_number=pull_number,
        comments=comments,
        evidence=evidence,
    )
    _publish_commit_status(
        client, repository=repository, head_sha=head_sha, evidence=evidence
    )
    return evidence


def _handle_qodo(
    event: dict[str, Any],
    client: Any,
    evidence: dict[str, Any],
    *,
    repository: str,
    pull_number: int,
) -> dict[str, Any]:
    comment = event["comment"]
    sender = event.get("sender")
    if not _matches_identity(
        comment.get("user"), login=QODO_LOGIN, user_id=QODO_ID
    ) or not _matches_identity(sender, login=QODO_LOGIN, user_id=QODO_ID):
        evidence.update(
            {
                "outcome": "REJECTED_UNTRUSTED_QODO_IDENTITY",
                "passed": False,
            }
        )
        return evidence

    comments = client.list_comments(repository, pull_number)
    status_comment = _find_status_comment(comments)
    if status_comment is None:
        evidence["outcome"] = "IGNORED_QODO_WITHOUT_FALLBACK_STATUS"
        return evidence

    status = parse_status_comment(status_comment.get("body"))
    head_sha = _normalize_sha(status.get("exact_head_sha"))
    body = _printable_comment_body(comment.get("body"))
    observed_shas = {match.lower() for match in FULL_SHA_PATTERN.findall(body)}
    if head_sha not in observed_shas:
        evidence.update(
            {
                "exact_head_sha": head_sha,
                "outcome": "IGNORED_QODO_RESULT_WITHOUT_EXACT_HEAD_BINDING",
                "passed": True,
            }
        )
        return evidence

    pull = client.get_pull(repository, pull_number)
    _, _, current_head = _pull_snapshot(pull)
    status.update(
        {
            "final_qodo_review_identity": QODO_LOGIN,
            "final_qodo_review_comment_id": _comment_id(comment),
            "final_qodo_review_sha": head_sha,
            "final_qodo_outcome": _classify_qodo_outcome(body),
            "qodo_request_status": "COMPLETED",
            "stale_or_superseded": current_head != head_sha,
            "outcome": "QODO_REVIEW_RECORDED",
            "passed": True,
            "run_id": evidence["run_id"],
            "run_attempt": evidence["run_attempt"],
            "run_url": evidence["run_url"],
            "event_comment_id": evidence["event_comment_id"],
        }
    )
    client.update_comment(
        repository,
        _comment_id(status_comment),
        render_status_comment(status),
    )
    _publish_commit_status(
        client, repository=repository, head_sha=head_sha, evidence=status
    )
    return status


def process_event(
    event: dict[str, Any],
    client: Any,
    *,
    repository: str,
    run_id: int,
    run_attempt: int,
    run_url: str,
    now: Callable[[], str] = _now_iso,
) -> dict[str, Any]:
    repository = _normalize_repository(repository)
    run_id = _positive_int(run_id, label="run id")
    run_attempt = _positive_int(run_attempt, label="run attempt")
    if not isinstance(event, dict):
        raise FallbackError("event payload must be an object")
    event_repository = event.get("repository")
    if not isinstance(event_repository, dict) or event_repository.get("full_name") != repository:
        raise FallbackError("event repository does not match GITHUB_REPOSITORY")
    issue = event.get("issue")
    comment = event.get("comment")
    if not isinstance(issue, dict) or not isinstance(comment, dict):
        raise FallbackError("issue_comment event payload is incomplete")
    pull_number = _positive_int(issue.get("number"), label="pull number")
    event_comment_id = _comment_id(comment)
    evidence = _default_evidence(
        repository=repository,
        pull_number=pull_number,
        run_id=run_id,
        run_attempt=run_attempt,
        run_url=run_url,
        event_comment_id=event_comment_id,
    )
    if "pull_request" not in issue:
        evidence["outcome"] = "IGNORED_NON_PULL_REQUEST_COMMENT"
        return evidence

    body = _printable_comment_body(comment.get("body"))
    if _matches_identity(
        comment.get("user"), login=QODO_LOGIN, user_id=QODO_ID
    ) or _matches_identity(event.get("sender"), login=QODO_LOGIN, user_id=QODO_ID):
        return _handle_qodo(
            event,
            client,
            evidence,
            repository=repository,
            pull_number=pull_number,
        )

    if _rate_limit_marker_present(body):
        return _handle_coderabbit(
            event,
            client,
            evidence,
            repository=repository,
            pull_number=pull_number,
            now=now,
        )

    evidence["outcome"] = "IGNORED_UNRELATED_COMMENT"
    return evidence


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-path", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repository = args.repository
    run_id: str | int = args.run_id
    run_attempt: str | int = args.run_attempt
    try:
        event = json.loads(args.event_path.read_text(encoding="utf-8"))
        client = GitHubApi(os.environ.get("GITHUB_TOKEN", ""))
        result = process_event(
            event,
            client,
            repository=repository,
            run_id=_positive_int(run_id, label="run id"),
            run_attempt=_positive_int(run_attempt, label="run attempt"),
            run_url=args.run_url,
        )
    except Exception as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "repository": repository,
            "pull_number": None,
            "exact_head_sha": None,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "run_url": args.run_url,
            "event_comment_id": None,
            "coderabbit_status": "UNKNOWN",
            "qodo_request_status": "NOT_REQUESTED",
            "stale_or_superseded": False,
            "outcome": "WORKFLOW_ERROR",
            "passed": False,
            "merge_authority": False,
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
    write_json(args.output, result)
    if not result.get("passed", False):
        raise SystemExit(
            f"CML reviewer fallback failed closed: {result.get('outcome', 'UNKNOWN')}"
        )
    print(
        f"CML reviewer fallback outcome={result['outcome']} "
        f"head={result.get('exact_head_sha')}"
    )


if __name__ == "__main__":
    main()
