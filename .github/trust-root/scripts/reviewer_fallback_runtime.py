#!/usr/bin/env python3
"""Protected runtime for native and reconciled reviewer-fallback events."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

RECONCILE_PATH = Path(__file__).with_name("reviewer_fallback_reconcile.py")
RECONCILE_SPEC = importlib.util.spec_from_file_location(
    "cml_reviewer_fallback_reconcile", RECONCILE_PATH
)
if RECONCILE_SPEC is None or RECONCILE_SPEC.loader is None:
    raise RuntimeError("cannot load reviewer fallback reconciler")
rec = importlib.util.module_from_spec(RECONCILE_SPEC)
sys.modules[RECONCILE_SPEC.name] = rec
RECONCILE_SPEC.loader.exec_module(rec)

rf = rec.rf
ALLOWED_ARTIFACT_RUN_EVENTS = rf.SUPPORTED_EVENT_NAMES | {"workflow_dispatch"}


class RuntimeGitHubApi(rec.ReconcileGitHubApi):
    """Authenticate native and workflow-dispatch fallback artifacts."""

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
            raise rf.FallbackError("workflow run response is invalid")
        if (
            run.get("name") != rf.WORKFLOW_NAME
            or run.get("event") not in ALLOWED_ARTIFACT_RUN_EVENTS
        ):
            raise rf.FallbackError("artifact run is not the reviewer-fallback workflow")
        if run.get("path") != rf.WORKFLOW_PATH:
            raise rf.FallbackError("artifact run uses an unexpected workflow path")
        if run.get("head_branch") != "main":
            raise rf.FallbackError("artifact run did not execute from main")
        if run.get("run_attempt") != run_attempt:
            raise rf.FallbackError("artifact run attempt mismatch")
        repository_payload = run.get("repository")
        if (
            not isinstance(repository_payload, dict)
            or repository_payload.get("full_name") != repository
        ):
            raise rf.FallbackError("artifact run repository mismatch")
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            raise rf.FallbackError(
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
                raise rf.FallbackError("workflow artifact response is invalid")
            page_items = response["artifacts"]
            if not all(isinstance(item, dict) for item in page_items):
                raise rf.FallbackError("workflow artifact entry is invalid")
            artifacts.extend(page_items)
            if len(page_items) < 100:
                break
        else:
            raise rf.FallbackError(
                "workflow artifact pagination exceeded the safe bound"
            )
        matches = [
            item
            for item in artifacts
            if item.get("name") == expected_name and item.get("expired") is False
        ]
        if len(matches) != 1:
            raise rf.FallbackError(
                "exact reviewer-fallback artifact is missing or ambiguous"
            )
        artifact_id = rf._positive_int(matches[0].get("id"), label="artifact id")
        archive = self._request_bytes(
            "GET",
            f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip",
        )
        try:
            with rf.core.zipfile.ZipFile(rf.core.io.BytesIO(archive)) as bundle:
                names = [
                    name
                    for name in bundle.namelist()
                    if Path(name).name == "reviewer-fallback-evidence.json"
                ]
                if len(names) != 1:
                    raise rf.FallbackError(
                        "fallback artifact evidence file is missing or ambiguous"
                    )
                payload = rf._json_object(
                    bundle.read(names[0]), label="fallback artifact evidence"
                )
        except rf.core.zipfile.BadZipFile as exc:
            raise rf.FallbackError("fallback artifact ZIP is invalid") from exc
        return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--repository", required=True)
        target.add_argument("--run-id", required=True)
        target.add_argument("--run-attempt", required=True)
        target.add_argument("--run-url", required=True)
        target.add_argument("--output", type=Path, required=True)

    native = subparsers.add_parser("native")
    common(native)
    native.add_argument("--event-path", type=Path, required=True)

    discover = subparsers.add_parser("discover")
    common(discover)
    discover.add_argument("--ref", required=True)

    reconcile = subparsers.add_parser("reconcile")
    common(reconcile)
    reconcile.add_argument("--pull-number", required=True)
    reconcile.add_argument("--comment-id", required=True)
    return parser


def _workflow_error(args: argparse.Namespace, exc: Exception) -> dict[str, Any]:
    return {
        "schema_version": rf.SCHEMA_VERSION,
        "repository": args.repository,
        "pull_number": None,
        "exact_head_sha": None,
        "event_run_id": args.run_id,
        "event_run_attempt": args.run_attempt,
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


def main() -> None:
    args = _parser().parse_args()
    try:
        run_id = rf._positive_int(args.run_id, label="run id")
        run_attempt = rf._positive_int(args.run_attempt, label="run attempt")
        client = RuntimeGitHubApi(os.environ.get("GITHUB_TOKEN", ""))
        if args.command == "native":
            event_name = os.environ.get("CML_EVENT_NAME") or os.environ.get(
                "GITHUB_EVENT_NAME", "issue_comment"
            )
            raw_event = rf._json_object(
                args.event_path.read_bytes(), label="GitHub event payload"
            )
            event = rf.normalize_event_payload(event_name, raw_event)
            result = rf.process_event(
                event,
                client,
                repository=args.repository,
                run_id=run_id,
                run_attempt=run_attempt,
                run_url=args.run_url,
            )
        elif args.command == "discover":
            result = rec.discover(
                client,
                repository=args.repository,
                run_id=run_id,
                run_attempt=run_attempt,
                run_url=args.run_url,
                ref=args.ref,
            )
        else:
            result = rec.reconcile(
                client,
                repository=args.repository,
                pull_number=rf._positive_int(args.pull_number, label="pull number"),
                comment_id=rf._positive_int(args.comment_id, label="comment id"),
                run_id=run_id,
                run_attempt=run_attempt,
                run_url=args.run_url,
            )
    except Exception as exc:
        result = _workflow_error(args, exc)
    rf.write_json(args.output, result)
    if not result.get("passed", False):
        raise SystemExit(
            f"CML reviewer fallback runtime failed closed: "
            f"{result.get('outcome', 'UNKNOWN')}"
        )
    print(
        f"CML reviewer fallback runtime outcome={result['outcome']} "
        f"pull={result.get('pull_number') or result.get('selected_pull_number')}"
    )


if __name__ == "__main__":
    main()
