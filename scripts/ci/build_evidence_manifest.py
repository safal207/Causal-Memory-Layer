#!/usr/bin/env python3
"""Build a deterministic SHA-256 manifest for exact-head CI evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from scripts.ci.assert_exact_head import normalize_sha, write_json_atomic

REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
EVENT_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


class EvidenceError(ValueError):
    """Raised when evidence is absent, ambiguous, or unsafe to hash."""


def _require_text(value: str, *, label: str, pattern: re.Pattern[str] | None = None) -> str:
    normalized = value.strip()
    if not normalized or any(ord(character) < 32 for character in normalized):
        raise EvidenceError(f"{label} must be non-empty text without control characters")
    if pattern is not None and not pattern.fullmatch(normalized):
        raise EvidenceError(f"{label} has an invalid format")
    return normalized


def _positive_int(value: str, *, label: str, allow_zero: bool = False) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise EvidenceError(f"{label} must be an integer") from exc
    minimum = 0 if allow_zero else 1
    if parsed < minimum:
        raise EvidenceError(f"{label} must be >= {minimum}")
    return parsed


def _collect_files(root: Path, *, excluded: Path | None = None) -> list[dict[str, Any]]:
    if not root.is_dir():
        raise EvidenceError(f"artifacts root does not exist or is not a directory: {root}")

    entries: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for candidate in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if candidate.is_symlink():
            raise EvidenceError(f"symbolic links are forbidden in evidence: {candidate}")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise EvidenceError(f"non-regular evidence entry is forbidden: {candidate}")
        if excluded is not None and candidate.resolve() == excluded:
            continue

        relative = candidate.relative_to(root).as_posix()
        if any(ord(character) < 32 for character in relative):
            raise EvidenceError(f"evidence path contains a control character: {relative!r}")
        canonical_path = relative.casefold()
        if canonical_path in seen_paths:
            raise EvidenceError(f"case-insensitive duplicate evidence path: {relative}")
        seen_paths.add(canonical_path)

        content = candidate.read_bytes()
        entries.append(
            {
                "path": relative,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )

    if not entries:
        raise EvidenceError("artifacts root contains no evidence files")
    return entries


def _verify_required_patterns(
    root: Path,
    patterns: Iterable[str],
    artifacts: Iterable[dict[str, Any]],
) -> None:
    collected_paths = {str(artifact["path"]) for artifact in artifacts}
    for raw_pattern in patterns:
        pattern = _require_text(raw_pattern, label="required evidence pattern")
        pattern_path = PurePosixPath(pattern)
        if pattern_path.is_absolute() or ".." in pattern_path.parts:
            raise EvidenceError(f"required evidence pattern escapes the artifacts root: {pattern}")

        matched_paths = {
            candidate.relative_to(root).as_posix()
            for candidate in root.glob(pattern)
            if candidate.is_file() and not candidate.is_symlink()
        }
        if not matched_paths.intersection(collected_paths):
            raise EvidenceError(
                f"required evidence pattern matched no files eligible for hashing: {pattern}"
            )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _verify_json_bindings(
    root: Path,
    artifacts: Iterable[dict[str, Any]],
    *,
    tested_sha: str,
) -> None:
    exact_head_reports = 0
    for artifact in artifacts:
        relative = artifact["path"]
        if not relative.endswith(".json"):
            continue
        path = root / relative
        try:
            payload = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_json_object,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as exc:
            raise EvidenceError(f"invalid JSON evidence at {relative}: {exc}") from exc
        if not isinstance(payload, dict):
            continue

        bound_sha = payload.get("tested_sha")
        if bound_sha is not None:
            try:
                normalized = normalize_sha(str(bound_sha), label=f"{relative} tested SHA")
            except ValueError as exc:
                raise EvidenceError(str(exc)) from exc
            if normalized != tested_sha:
                raise EvidenceError(
                    f"stale JSON evidence at {relative}: {normalized} != {tested_sha}"
                )

        if payload.get("schema_version") == "cml-exact-head-evidence-v1":
            exact_head_reports += 1
            try:
                expected = normalize_sha(
                    str(payload.get("expected_sha", "")),
                    label=f"{relative} expected SHA",
                )
                actual = normalize_sha(
                    str(payload.get("actual_sha", "")),
                    label=f"{relative} actual SHA",
                )
            except ValueError as exc:
                raise EvidenceError(str(exc)) from exc
            if expected != tested_sha or actual != tested_sha or payload.get("matched") is not True:
                raise EvidenceError(f"invalid exact-head binding at {relative}")

    if exact_head_reports == 0:
        raise EvidenceError("evidence contains no exact-head report")


def build_manifest(
    *,
    artifacts_root: Path,
    repository: str,
    source_repository: str,
    tested_sha: str,
    event_name: str,
    run_id: str,
    run_attempt: str,
    change_number: str,
    workflow_ref: str,
    required_patterns: Iterable[str] = (),
    output_path: Path | None = None,
) -> dict[str, Any]:
    root = artifacts_root.resolve()
    excluded = output_path.resolve() if output_path is not None else None
    normalized_sha = normalize_sha(tested_sha, label="tested SHA")
    artifacts = _collect_files(root, excluded=excluded)
    _verify_required_patterns(root, required_patterns, artifacts)
    _verify_json_bindings(root, artifacts, tested_sha=normalized_sha)
    return {
        "schema_version": "cml-ci-evidence-manifest-v1",
        "algorithm": "sha256",
        "repository": _require_text(repository, label="repository", pattern=REPOSITORY_PATTERN),
        "source_repository": _require_text(
            source_repository,
            label="source repository",
            pattern=REPOSITORY_PATTERN,
        ),
        "tested_sha": normalized_sha,
        "event_name": _require_text(event_name, label="event name", pattern=EVENT_PATTERN),
        "run_id": _positive_int(run_id, label="run id"),
        "run_attempt": _positive_int(run_attempt, label="run attempt"),
        "change_number": _positive_int(
            change_number,
            label="change number",
            allow_zero=True,
        ),
        "workflow_ref": _require_text(workflow_ref, label="workflow ref"),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-root", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--tested-sha", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--change-number", default="0")
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--require", action="append", default=[], dest="required_patterns")
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        manifest = build_manifest(
            artifacts_root=args.artifacts_root,
            repository=args.repository,
            source_repository=args.source_repository,
            tested_sha=args.tested_sha,
            event_name=args.event_name,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            change_number=args.change_number,
            workflow_ref=args.workflow_ref,
            required_patterns=args.required_patterns,
            output_path=args.output,
        )
        write_json_atomic(args.output, manifest)
    except (EvidenceError, ValueError) as exc:
        raise SystemExit(f"evidence manifest failed closed: {exc}") from exc
    print(f"Evidence manifest contains {manifest['artifact_count']} files")


if __name__ == "__main__":
    main()
