#!/usr/bin/env python3
"""Prove that a CI checkout is the exact commit it claims to validate."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class ExactHeadError(ValueError):
    """Raised when exact-head evidence cannot be established."""


def normalize_sha(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if not SHA_PATTERN.fullmatch(normalized):
        raise ExactHeadError(f"{label} must be a full 40-character hexadecimal SHA")
    return normalized


def resolve_git_head(repository_root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown git error"
        raise ExactHeadError(f"cannot resolve checked-out HEAD: {detail}")
    return normalize_sha(completed.stdout, label="checked-out HEAD")


def build_report(*, expected_sha: str, actual_sha: str) -> dict[str, Any]:
    expected = normalize_sha(expected_sha, label="expected SHA")
    actual = normalize_sha(actual_sha, label="checked-out HEAD")
    if actual != expected:
        raise ExactHeadError(
            f"checkout is not exact-head bound: expected {expected}, checked out {actual}"
        )
    return {
        "schema_version": "cml-exact-head-evidence-v1",
        "expected_sha": expected,
        "actual_sha": actual,
        "matched": True,
    }


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(serialized)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", required=True, help="Expected exact commit SHA")
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path.cwd(),
        help="Git repository root (default: current directory)",
    )
    parser.add_argument("--output", type=Path, required=True, help="Evidence JSON path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        actual = resolve_git_head(args.repository_root)
        report = build_report(expected_sha=args.expected, actual_sha=actual)
        write_json_atomic(args.output, report)
    except ExactHeadError as exc:
        raise SystemExit(f"exact-head verification failed: {exc}") from exc
    print(f"Exact-head verified: {report['actual_sha']}")


if __name__ == "__main__":
    main()
