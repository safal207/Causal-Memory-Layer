#!/usr/bin/env python3
"""Authoritative fail-closed entrypoint for the reviewer fallback workflow."""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
import sys
import zipfile
from pathlib import Path
from typing import Any, Callable

CORE_PATH = Path(__file__).with_name("reviewer_fallback.py")
CORE_SPEC = importlib.util.spec_from_file_location("cml_reviewer_fallback_core", CORE_PATH)
if CORE_SPEC is None or CORE_SPEC.loader is None:
    raise RuntimeError("cannot load reviewer fallback core")
core = importlib.util.module_from_spec(CORE_SPEC)
sys.modules[CORE_SPEC.name] = core
CORE_SPEC.loader.exec_module(core)

# Re-export the reviewed core API so tests and callers exercise this authoritative
# entrypoint without duplicating the underlying state machine.
for _name in dir(core):
    if not _name.startswith("__"):
        globals().setdefault(_name, getattr(core, _name))


class GitHubApi(core.GitHubApi):
    """GitHub client with explicit fail-closed artifact pagination."""

    def load_fallback_artifact(
        self,
        repository: str,
        pull_number: int,
        run_id: int,
        run_attempt: int,
    ) -> dict[str, Any]:
        run = self._request_json(
            "GET", f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
        )
        if not isinstance(run, dict):
            raise core.FallbackError("workflow run response is invalid")
        if run.get("name") != core.WORKFLOW_NAME or run.get("event") != "issue_comment":
            raise core.FallbackError("artifact run is not the reviewer-fallback workflow")
        if run.get("path") != core.WORKFLOW_PATH:
            raise core.FallbackError("artifact run uses an unexpected workflow path")
        if run.get("head_branch") != "main":
            raise core.FallbackError("artifact run did not execute from main")
        if run.get("run_attempt") != run_attempt:
            raise core.FallbackError("artifact run attempt mismatch")
        repository_payload = run.get("repository")
        if (
            not isinstance(repository_payload, dict)
            or repository_payload.get("full_name") != repository
        ):
            raise core.FallbackError("artifact run repository mismatch")
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            raise core.FallbackError("artifact run is not a completed successful workflow")

        expected_name = f"cml-reviewer-fallback-pr{pull_number}-{run_id}-{run_attempt}"
        artifacts: list[dict[str, Any]] = []
        for page in range(1, 11):
            response = self._request_json(
                "GET",
                f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/artifacts"
                f"?per_page=100&page={page}",
            )
            if not isinstance(response, dict) or not isinstance(
                response.get("artifacts"), list
            ):
                raise core.FallbackError("workflow artifact response is invalid")
            page_items = response["artifacts"]
            if not all(isinstance(item, dict) for item in page_items):
                raise core.FallbackError("workflow artifact entry is invalid")
            artifacts.extend(page_items)
            if len(page_items) < 100:
                break
        else:
            raise core.FallbackError("workflow artifact pagination exceeded the safe bound")

        matches = [
            item
            for item in artifacts
            if item.get("name") == expected_name and item.get("expired") is False
        ]
        if len(matches) != 1:
            raise core.FallbackError(
                "exact reviewer-fallback artifact is missing or ambiguous"
            )
        artifact_id = core._positive_int(matches[0].get("id"), label="artifact id")
        archive = self._request_bytes(
            "GET",
            f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip",
        )
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                names = [
                    name
                    for name in bundle.namelist()
                    if Path(name).name == "reviewer-fallback-evidence.json"
                ]
                if len(names) != 1:
                    raise core.FallbackError(
                        "fallback artifact evidence file is missing or ambiguous"
                    )
                payload = core._json_object(
                    bundle.read(names[0]), label="fallback artifact evidence"
                )
        except zipfile.BadZipFile as exc:
            raise core.FallbackError("fallback artifact ZIP is invalid") from exc
        return payload


def _extract_reviewed_sha(body: str) -> str:
    """Require exactly one structured reviewed-commit occurrence."""

    matches: list[str] = []
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(">"):
            continue
        for pattern in core.REVIEWED_SHA_PATTERNS:
            match = pattern.fullmatch(line)
            if match:
                matches.append(core._normalize_sha(match.group(1)))
    if not matches:
        raise core.FallbackError("Qodo result lacks a structured reviewed-commit field")
    if len(matches) != 1:
        raise core.FallbackError(
            "Qodo result must contain exactly one structured reviewed-commit field"
        )
    return matches[0]


def _publish_commit_status(
    client: Any,
    *,
    repository: str,
    head_sha: str | None,
    evidence: dict[str, Any],
) -> None:
    """Publish failures only; evidence delivery can never become merge authority."""

    if head_sha is None or evidence.get("passed") is True:
        return
    outcome = evidence["outcome"]
    if outcome == "PROVIDER_EVIDENCE_UNAVAILABLE":
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
        target_url=evidence["event_run_url"],
    )


# Patch the core module's global call sites before invoking its state machine.
core.GitHubApi = GitHubApi
core._extract_reviewed_sha = _extract_reviewed_sha
core._publish_commit_status = _publish_commit_status


def process_event(
    event: dict[str, Any],
    client: Any,
    *,
    repository: str,
    run_id: int,
    run_attempt: int,
    run_url: str,
    now: Callable[[], str] = core._now_iso,
) -> dict[str, Any]:
    """Route an event while forbidding edited Qodo lifecycle completion."""

    action = event.get("action")
    if action not in {"created", "edited"}:
        raise core.FallbackError("issue_comment action must be created or edited")

    issue = event.get("issue")
    comment = event.get("comment")
    if not isinstance(issue, dict) or not isinstance(comment, dict):
        raise core.FallbackError("issue_comment event payload is incomplete")

    is_qodo = core._matches_identity(
        comment.get("user"), login=core.QODO_LOGIN, user_id=core.QODO_ID
    ) or core._matches_identity(
        event.get("sender"), login=core.QODO_LOGIN, user_id=core.QODO_ID
    )
    if is_qodo and action != "created":
        evidence = core._default_evidence(
            repository=core._normalize_repository(repository),
            pull_number=core._positive_int(issue.get("number"), label="pull number"),
            run_id=core._positive_int(run_id, label="run id"),
            run_attempt=core._positive_int(run_attempt, label="run attempt"),
            run_url=run_url,
            event_comment_id=core._comment_id(comment),
        )
        evidence.update(
            {
                "outcome": "REJECTED_EDITED_QODO_RESULT",
                "passed": False,
                "merge_authority": False,
            }
        )
        return evidence

    return core.process_event(
        event,
        client,
        repository=repository,
        run_id=run_id,
        run_attempt=run_attempt,
        run_url=run_url,
        now=now,
    )


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
        event = core._json_object(
            args.event_path.read_bytes(), label="GitHub event payload"
        )
        client = GitHubApi(os.environ.get("GITHUB_TOKEN", ""))
        result = process_event(
            event,
            client,
            repository=repository,
            run_id=core._positive_int(run_id, label="run id"),
            run_attempt=core._positive_int(run_attempt, label="run attempt"),
            run_url=args.run_url,
        )
    except Exception as exc:
        result = {
            "schema_version": core.SCHEMA_VERSION,
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
            "outcome": "WORKFLOW_ERROR",
            "passed": False,
            "merge_authority": False,
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
    core.write_json(args.output, result)
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
