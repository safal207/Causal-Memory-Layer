#!/usr/bin/env python3
"""Protected event adapter for the intrinsically strict reviewer fallback core."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

CORE_PATH = Path(__file__).with_name("reviewer_fallback.py")
CORE_SPEC = importlib.util.spec_from_file_location("cml_reviewer_fallback_core", CORE_PATH)
if CORE_SPEC is None or CORE_SPEC.loader is None:
    raise RuntimeError("cannot load reviewer fallback core")
core = importlib.util.module_from_spec(CORE_SPEC)
sys.modules[CORE_SPEC.name] = core
CORE_SPEC.loader.exec_module(core)

for _name in dir(core):
    if not _name.startswith("__"):
        globals()[_name] = getattr(core, _name)

SUPPORTED_EVENT_NAMES = frozenset(
    {
        "issue_comment",
        "pull_request_review",
        "pull_request_review_comment",
    }
)
ALLOWED_ARTIFACT_RUN_EVENTS = SUPPORTED_EVENT_NAMES


def _required_object(payload: object, key: str, *, label: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise core.FallbackError(f"{label} payload must be an object")
    value = payload.get(key)
    if not isinstance(value, dict):
        raise core.FallbackError(f"{label} {key} must be an object")
    return value


def _normalize_review_event(
    event: dict[str, Any], *, event_name: str, source_key: str
) -> dict[str, Any]:
    pull = _required_object(event, "pull_request", label=event_name)
    source = _required_object(event, source_key, label=event_name)
    pull_number = core._positive_int(pull.get("number"), label="pull number")

    raw_action = event.get("action")
    if event_name == "pull_request_review":
        action_map = {"submitted": "created", "edited": "edited"}
    else:
        action_map = {"created": "created", "edited": "edited"}
    try:
        normalized_action = action_map[raw_action]
    except (KeyError, TypeError) as exc:
        raise core.FallbackError(
            f"unsupported {event_name} action: {raw_action!r}"
        ) from exc

    comment = dict(source)
    if event_name == "pull_request_review":
        comment["created_at"] = source.get("submitted_at") or source.get("created_at")

    if event_name == "pull_request_review_comment" and core._matches_identity(
        comment.get("user"), login=core.QODO_LOGIN, user_id=core.QODO_ID
    ):
        # An inline comment is partial evidence and cannot complete the Qodo lifecycle.
        normalized_action = "edited"

    pull_url = pull.get("url")
    if not isinstance(pull_url, str) or not pull_url:
        pull_url = f"https://api.github.com/repos/unknown/unknown/pulls/{pull_number}"

    return {
        "action": normalized_action,
        "repository": event.get("repository"),
        "issue": {
            "number": pull_number,
            "pull_request": {"url": pull_url},
        },
        "comment": comment,
        "sender": event.get("sender"),
        "cml_original_event_name": event_name,
    }


def normalize_event_payload(event_name: str, event: object) -> dict[str, Any]:
    """Normalize trusted GitHub PR event surfaces into the core comment contract."""

    if event_name not in SUPPORTED_EVENT_NAMES:
        raise core.FallbackError(f"unsupported reviewer fallback event: {event_name}")
    if not isinstance(event, dict):
        raise core.FallbackError("GitHub event payload must be an object")
    if event_name == "issue_comment":
        normalized = dict(event)
        normalized["cml_original_event_name"] = event_name
        return normalized
    if event_name == "pull_request_review":
        return _normalize_review_event(
            event, event_name=event_name, source_key="review"
        )
    return _normalize_review_event(
        event, event_name=event_name, source_key="comment"
    )


class MultiSurfaceGitHubApi(core.GitHubApi):
    """Authenticate artifacts from every explicitly supported workflow event."""

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
        if (
            run.get("name") != core.WORKFLOW_NAME
            or run.get("event") not in ALLOWED_ARTIFACT_RUN_EVENTS
        ):
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
            raise core.FallbackError(
                "artifact run is not a completed successful workflow"
            )

        expected_name = (
            f"cml-reviewer-fallback-pr{pull_number}-{run_id}-{run_attempt}"
        )
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
            raise core.FallbackError(
                "workflow artifact pagination exceeded the safe bound"
            )
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
            with core.zipfile.ZipFile(core.io.BytesIO(archive)) as bundle:
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
        except core.zipfile.BadZipFile as exc:
            raise core.FallbackError("fallback artifact ZIP is invalid") from exc
        return payload


def main() -> None:
    """Normalize the event surface, then execute the unchanged strict state machine."""

    args = core.parse_args()
    repository = args.repository
    run_id: str | int = args.run_id
    run_attempt: str | int = args.run_attempt
    event_name = os.environ.get("CML_EVENT_NAME") or os.environ.get(
        "GITHUB_EVENT_NAME", "issue_comment"
    )
    try:
        raw_event = core._json_object(
            args.event_path.read_bytes(), label="GitHub event payload"
        )
        event = normalize_event_payload(event_name, raw_event)
        client = MultiSurfaceGitHubApi(os.environ.get("GITHUB_TOKEN", ""))
        result = core.process_event(
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
