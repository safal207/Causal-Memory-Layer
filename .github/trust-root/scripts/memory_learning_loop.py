#!/usr/bin/env python3
"""Protected entrypoint for the post-merge CML Memory Learning Loop."""

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

import memory_learning_core as core  # noqa: E402
import memory_learning_github as github  # noqa: E402

REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise core.LearningLoopError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_event(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise core.LearningLoopError(f"cannot read GitHub event payload: {exc}") from exc
    return core.mapping(payload, label="GitHub event payload")


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
    result.add_argument("--pull-number")
    result.add_argument("--run-id", required=True)
    result.add_argument("--run-attempt", required=True)
    result.add_argument("--run-url", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> None:
    args = parser().parse_args()
    try:
        repository = args.repository
        if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
            raise core.LearningLoopError("repository must use owner/name format")
        run_id = core.positive_int(args.run_id, label="run id")
        run_attempt = core.positive_int(args.run_attempt, label="run attempt")
        event = read_event(args.event_path)
        if args.pull_number is not None:
            pull_number = core.positive_int(args.pull_number, label="pull number")
        else:
            event_pull = core.mapping(
                event.get("pull_request"), label="event pull request"
            )
            pull_number = core.positive_int(
                event_pull.get("number"), label="pull number"
            )
        result = github.propose(
            api=github.GitHubApi(os.environ.get("GITHUB_TOKEN", "")),
            repository=repository,
            pull_number=pull_number,
            run_id=run_id,
            run_attempt=run_attempt,
            run_url=args.run_url,
        )
    except Exception as exc:
        result = {
            "schema_version": "cml-learning-loop-evidence-v1",
            "repository": args.repository,
            "pull_number": args.pull_number,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "run_url": args.run_url,
            "outcome": "LEARNING_LOOP_ERROR",
            "skip_reason": None,
            "memory_path": None,
            "memory_pack_id": None,
            "branch": None,
            "proposal_pull_number": None,
            "proposal_pull_url": None,
            "validation_workflows": list(github.VALIDATION_WORKFLOWS),
            "validation_dispatched": False,
            "direct_main_write": False,
            "merge_authority": False,
            "execution_authority": False,
            "passed": False,
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
    write_json(args.output, result)
    if not result.get("passed", False):
        raise SystemExit(
            f"CML memory learning loop failed closed: {result.get('outcome')}"
        )
    print(
        f"CML memory learning loop outcome={result['outcome']} "
        f"source_pr={result.get('pull_number')} "
        f"proposal_pr={result.get('proposal_pull_number')}"
    )


if __name__ == "__main__":
    main()
