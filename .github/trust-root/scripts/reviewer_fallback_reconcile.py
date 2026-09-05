#!/usr/bin/env python3
"""Discover and reconcile missed canonical CodeRabbit rate-limit events."""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys
from pathlib import Path
from typing import Any

ENTRYPOINT_PATH = Path(__file__).with_name("reviewer_fallback_entrypoint.py")
ENTRYPOINT_SPEC = importlib.util.spec_from_file_location(
    "cml_reviewer_fallback_entrypoint", ENTRYPOINT_PATH
)
if ENTRYPOINT_SPEC is None or ENTRYPOINT_SPEC.loader is None:
    raise RuntimeError("cannot load reviewer fallback entrypoint")
rf = importlib.util.module_from_spec(ENTRYPOINT_SPEC)
sys.modules[ENTRYPOINT_SPEC.name] = rf
ENTRYPOINT_SPEC.loader.exec_module(rf)

DISCOVERY_SCHEMA_VERSION = "cml-reviewer-fallback-discovery-v1"
WORKFLOW_FILE = "reviewer-fallback.yml"


def _standalone_head_present(body: str, head_sha: str) -> bool:
    pattern = re.compile(
        rf"(?<![0-9a-fA-F]){re.escape(head_sha)}(?![0-9a-fA-F])",
        flags=re.IGNORECASE,
    )
    return pattern.search(body) is not None


def _trusted_bound_rate_limit_comment(
    comment: dict[str, Any], *, head_sha: str
) -> bool:
    if not rf._matches_identity(
        comment.get("user"), login=rf.CODE_RABBIT_LOGIN, user_id=rf.CODE_RABBIT_ID
    ):
        return False
    try:
        body = rf._printable_comment_body(comment.get("body"))
        rf._comment_id(comment)
        rf._timestamp(comment.get("created_at"), label="comment timestamp")
    except rf.FallbackError:
        return False
    return rf._rate_limit_marker_present(body) and _standalone_head_present(
        body, head_sha
    )


def _latest_bound_comment(
    comments: list[dict[str, Any]], *, head_sha: str
) -> dict[str, Any] | None:
    candidates: list[tuple[Any, int, dict[str, Any]]] = []
    for comment in comments:
        if not _trusted_bound_rate_limit_comment(comment, head_sha=head_sha):
            continue
        timestamp = rf._timestamp(comment.get("created_at"), label="comment timestamp")
        candidates.append((timestamp, rf._comment_id(comment), comment))
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], item[1]))[2]


class ReconcileGitHubApi(rf.MultiSurfaceGitHubApi):
    """GitHub operations used by the protected discovery/reconciliation path."""

    def list_open_pulls(self, repository: str) -> list[dict[str, Any]]:
        pulls: list[dict[str, Any]] = []
        for page in range(1, 11):
            payload = self._request_json(
                "GET",
                f"https://api.github.com/repos/{repository}/pulls"
                f"?state=open&base=main&sort=updated&direction=desc"
                f"&per_page=100&page={page}",
            )
            if not isinstance(payload, list) or not all(
                isinstance(item, dict) for item in payload
            ):
                raise rf.FallbackError("open pull-request response is invalid")
            pulls.extend(payload)
            if len(payload) < 100:
                return pulls
        raise rf.FallbackError("open pull-request pagination exceeded the safe bound")

    def dispatch_reconciliation(
        self,
        repository: str,
        *,
        pull_number: int,
        comment_id: int,
        ref: str,
    ) -> None:
        self._request_bytes(
            "POST",
            f"https://api.github.com/repos/{repository}/actions/workflows/"
            f"{WORKFLOW_FILE}/dispatches",
            payload={
                "ref": ref,
                "inputs": {
                    "pull_number": str(pull_number),
                    "coderabbit_comment_id": str(comment_id),
                },
            },
        )


def _pull_number(pull: dict[str, Any]) -> int:
    return rf._positive_int(pull.get("number"), label="pull number")


def _candidate_for_pull(
    client: ReconcileGitHubApi,
    repository: str,
    pull: dict[str, Any],
) -> tuple[int, str, dict[str, Any]] | None:
    pull_number = _pull_number(pull)
    state, base_ref, head_sha = rf._pull_snapshot(pull)
    if state != "open" or base_ref != "main":
        return None
    comments = client.list_comments(repository, pull_number)
    rate_limit_comment = _latest_bound_comment(comments, head_sha=head_sha)
    if rate_limit_comment is None:
        return None
    existing_request = rf._find_request_comment(
        client,
        comments,
        repository=repository,
        pull_number=pull_number,
        head_sha=head_sha,
    )
    if existing_request is not None:
        return None
    return pull_number, head_sha, rate_limit_comment


def discover(
    client: ReconcileGitHubApi,
    *,
    repository: str,
    run_id: int,
    run_attempt: int,
    run_url: str,
    ref: str,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "schema_version": DISCOVERY_SCHEMA_VERSION,
        "repository": repository,
        "event_run_id": run_id,
        "event_run_attempt": run_attempt,
        "event_run_url": run_url,
        "selected_pull_number": None,
        "selected_head_sha": None,
        "selected_coderabbit_comment_id": None,
        "dispatch_status": "NOT_DISPATCHED",
        "outcome": "DISCOVERY_NOOP",
        "passed": True,
        "merge_authority": False,
    }
    for pull in client.list_open_pulls(repository):
        candidate = _candidate_for_pull(client, repository, pull)
        if candidate is None:
            continue
        pull_number, head_sha, comment = candidate

        latest_pull = client.get_pull(repository, pull_number)
        latest_state, latest_base, latest_head = rf._pull_snapshot(latest_pull)
        if (
            latest_state != "open"
            or latest_base != "main"
            or latest_head != head_sha
        ):
            evidence.update(
                {
                    "selected_pull_number": pull_number,
                    "selected_head_sha": head_sha,
                    "selected_coderabbit_comment_id": rf._comment_id(comment),
                    "outcome": "DISCOVERY_REJECTED_SUPERSEDED_HEAD",
                    "passed": False,
                }
            )
            return evidence

        client.dispatch_reconciliation(
            repository,
            pull_number=pull_number,
            comment_id=rf._comment_id(comment),
            ref=ref,
        )
        evidence.update(
            {
                "selected_pull_number": pull_number,
                "selected_head_sha": head_sha,
                "selected_coderabbit_comment_id": rf._comment_id(comment),
                "dispatch_status": "DISPATCHED",
                "outcome": "RECONCILIATION_DISPATCHED",
            }
        )
        return evidence
    return evidence


def _reconcile_failure(
    *,
    repository: str,
    pull_number: int | None,
    run_id: int,
    run_attempt: int,
    run_url: str,
    comment_id: int | None,
    outcome: str,
    head_sha: str | None = None,
) -> dict[str, Any]:
    evidence = rf._default_evidence(
        repository=repository,
        pull_number=pull_number,
        run_id=run_id,
        run_attempt=run_attempt,
        run_url=run_url,
        event_comment_id=comment_id,
    )
    evidence.update(
        {
            "exact_head_sha": head_sha,
            "outcome": outcome,
            "passed": False,
            "merge_authority": False,
        }
    )
    return evidence


def reconcile(
    client: ReconcileGitHubApi,
    *,
    repository: str,
    pull_number: int,
    comment_id: int,
    run_id: int,
    run_attempt: int,
    run_url: str,
) -> dict[str, Any]:
    pull = client.get_pull(repository, pull_number)
    state, base_ref, head_sha = rf._pull_snapshot(pull)
    if state != "open":
        return _reconcile_failure(
            repository=repository,
            pull_number=pull_number,
            run_id=run_id,
            run_attempt=run_attempt,
            run_url=run_url,
            comment_id=comment_id,
            outcome="RECONCILE_REJECTED_PULL_REQUEST_NOT_OPEN",
            head_sha=head_sha,
        )
    if base_ref != "main":
        return _reconcile_failure(
            repository=repository,
            pull_number=pull_number,
            run_id=run_id,
            run_attempt=run_attempt,
            run_url=run_url,
            comment_id=comment_id,
            outcome="RECONCILE_REJECTED_UNEXPECTED_BASE",
            head_sha=head_sha,
        )

    comments = client.list_comments(repository, pull_number)
    comment = next(
        (item for item in comments if rf._comment_id(item) == comment_id), None
    )
    if comment is None:
        return _reconcile_failure(
            repository=repository,
            pull_number=pull_number,
            run_id=run_id,
            run_attempt=run_attempt,
            run_url=run_url,
            comment_id=comment_id,
            outcome="RECONCILE_REJECTED_COMMENT_NOT_FOUND",
            head_sha=head_sha,
        )
    if not _trusted_bound_rate_limit_comment(comment, head_sha=head_sha):
        evidence = _reconcile_failure(
            repository=repository,
            pull_number=pull_number,
            run_id=run_id,
            run_attempt=run_attempt,
            run_url=run_url,
            comment_id=comment_id,
            outcome="RECONCILE_REJECTED_UNTRUSTED_OR_STALE_COMMENT",
            head_sha=head_sha,
        )
        rf._publish_commit_status(
            client, repository=repository, head_sha=head_sha, evidence=evidence
        )
        return evidence

    event = {
        "action": "created",
        "repository": {"full_name": repository},
        "issue": {
            "number": pull_number,
            "pull_request": {"url": pull.get("url") or ""},
        },
        "comment": comment,
        "sender": comment.get("user"),
        "cml_original_event_name": "workflow_dispatch_reconciliation",
    }
    return rf.process_event(
        event,
        client,
        repository=repository,
        run_id=run_id,
        run_attempt=run_attempt,
        run_url=run_url,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--repository", required=True)
        target.add_argument("--run-id", required=True)
        target.add_argument("--run-attempt", required=True)
        target.add_argument("--run-url", required=True)
        target.add_argument("--output", type=Path, required=True)

    discover_parser = subparsers.add_parser("discover")
    common(discover_parser)
    discover_parser.add_argument("--ref", required=True)

    reconcile_parser = subparsers.add_parser("reconcile")
    common(reconcile_parser)
    reconcile_parser.add_argument("--pull-number", required=True)
    reconcile_parser.add_argument("--comment-id", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    repository = args.repository
    run_id: str | int = args.run_id
    run_attempt: str | int = args.run_attempt
    try:
        normalized_run_id = rf._positive_int(run_id, label="run id")
        normalized_attempt = rf._positive_int(run_attempt, label="run attempt")
        client = ReconcileGitHubApi(os.environ.get("GITHUB_TOKEN", ""))
        if args.command == "discover":
            result = discover(
                client,
                repository=repository,
                run_id=normalized_run_id,
                run_attempt=normalized_attempt,
                run_url=args.run_url,
                ref=args.ref,
            )
        else:
            result = reconcile(
                client,
                repository=repository,
                pull_number=rf._positive_int(
                    args.pull_number, label="pull number"
                ),
                comment_id=rf._positive_int(args.comment_id, label="comment id"),
                run_id=normalized_run_id,
                run_attempt=normalized_attempt,
                run_url=args.run_url,
            )
    except Exception as exc:
        result = {
            "schema_version": rf.SCHEMA_VERSION,
            "repository": repository,
            "pull_number": None,
            "exact_head_sha": None,
            "event_run_id": run_id,
            "event_run_attempt": run_attempt,
            "event_run_url": args.run_url,
            "event_comment_id": None,
            "coderabbit_status": "UNKNOWN",
            "qodo_request_status": "NOT_REQUESTED",
            "stale_or_superseded": False,
            "outcome": "RECONCILIATION_WORKFLOW_ERROR",
            "passed": False,
            "merge_authority": False,
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
    rf.write_json(args.output, result)
    if not result.get("passed", False):
        raise SystemExit(
            f"CML reviewer fallback reconciliation failed closed: "
            f"{result.get('outcome', 'UNKNOWN')}"
        )
    print(
        f"CML reviewer fallback reconciliation outcome={result['outcome']} "
        f"pull={result.get('pull_number') or result.get('selected_pull_number')}"
    )


if __name__ == "__main__":
    main()
