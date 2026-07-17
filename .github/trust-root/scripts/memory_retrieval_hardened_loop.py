#!/usr/bin/env python3
"""Event-only protected entrypoint for hardened CML Retrieval v0.1.1."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import memory_retrieval_core as core  # noqa: E402
import memory_retrieval_github as legacy  # noqa: E402
import memory_retrieval_hardened as hardened  # noqa: E402

REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise core.RetrievalError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_event(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise core.RetrievalError(
            "cannot read GitHub pull-request event payload"
        ) from exc
    if not isinstance(payload, dict):
        raise core.RetrievalError("GitHub event payload must be an object")
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--event-path", type=Path, required=True)
    result.add_argument("--repository", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--run-attempt", required=True)
    result.add_argument("--run-url", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def _positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool):
        raise core.RetrievalError(f"{label} must be an integer")
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise core.RetrievalError(f"{label} must be an integer") from exc
    if parsed < 1:
        raise core.RetrievalError(f"{label} must be positive")
    return parsed


def _failure_result(args: argparse.Namespace, exc: Exception) -> dict[str, Any]:
    return {
        "schema_version": core.SCHEMA_VERSION,
        "repository": args.repository,
        "pull_number": None,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "run_url": args.run_url,
        "outcome": "RETRIEVAL_ERROR",
        "skip_reason": None,
        "accepted_count": None,
        "publishable_count": 0,
        "withheld_count": None,
        "rejected_count": None,
        "rejected": [],
        "privacy_summary_redacted": True,
        "selected": [],
        "comment_action": None,
        "comment_id": None,
        "duplicate_managed_comments": 0,
        "direct_main_write": False,
        "approval_authority": False,
        "merge_authority": False,
        "execution_authority": False,
        "passed": False,
        "error": {
            "type": type(exc).__name__,
            "message": "CML retrieval failed closed",
        },
    }


def main() -> None:
    args = parser().parse_args()
    try:
        repository = args.repository
        if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
            raise core.RetrievalError("repository must use owner/name format")
        event = read_event(args.event_path)
        pull = event.get("pull_request")
        if not isinstance(pull, dict):
            raise core.RetrievalError(
                "event pull_request must be an object"
            )
        pull_number = _positive_int(pull.get("number"), label="pull number")
        result = hardened.retrieve_for_pull(
            api=legacy.GitHubApi(os.environ.get("GITHUB_TOKEN", "")),
            repository=repository,
            pull_number=pull_number,
            run_id=_positive_int(args.run_id, label="run id"),
            run_attempt=_positive_int(args.run_attempt, label="run attempt"),
            run_url=args.run_url,
        )
    except Exception as exc:
        result = _failure_result(args, exc)
    write_json(args.output, result)
    if not result.get("passed", False):
        raise SystemExit(
            f"CML retrieval failed closed: {result.get('outcome')}"
        )
    print(
        f"CML retrieval outcome={result['outcome']} "
        f"pull={result.get('pull_number')} "
        f"selected={len(result.get('selected', []))} "
        f"comment={result.get('comment_action')}"
    )


if __name__ == "__main__":
    main()
