#!/usr/bin/env python3
"""Verify that a pull request preserves the protected CML CI trust contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SCHEMA_VERSION = "cml-trust-root-verification-v2"
MANIFEST_SCHEMA = "cml-trust-root-files-v1"
PROTECTED_EXACT = {".github/workflows/trusted-pr-gate.yml"}
PROTECTED_PREFIXES = (".github/trust-root/",)
WORKFLOW_PREFIX = ".github/workflows/"
DANGEROUS_IMPORT_ROOTS = frozenset(sys.stdlib_module_names) | {
    "scripts",
    "sitecustomize",
    "usercustomize",
    "yaml",
}


class TrustRootError(ValueError):
    """Raised when the protected CI contract cannot be established."""


def normalize_sha(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if not SHA_PATTERN.fullmatch(normalized):
        raise TrustRootError(f"{label} must be a full 40-character hexadecimal SHA")
    return normalized


def positive_int(value: str | int, *, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise TrustRootError(f"{label} must be an integer") from exc
    if parsed < 1:
        raise TrustRootError(f"{label} must be >= 1")
    return parsed


def require_repository(value: str) -> str:
    normalized = value.strip()
    if not REPOSITORY_PATTERN.fullmatch(normalized):
        raise TrustRootError("repository has an invalid format")
    return normalized


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrustRootError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustRootError(f"cannot read trusted JSON {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise TrustRootError(f"trusted JSON must contain an object: {path}")
    return payload


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
        raise TrustRootError(f"cannot resolve subject HEAD: {detail}")
    return normalize_sha(completed.stdout, label="subject HEAD")


def file_identity(path: Path) -> tuple[str, str, int]:
    if path.is_symlink():
        raise TrustRootError(f"protected file cannot be a symbolic link: {path}")
    if not path.is_file():
        raise TrustRootError(f"protected file is missing or not a regular file: {path}")
    content = path.read_bytes()
    completed = subprocess.run(
        ["git", "hash-object", "--stdin"],
        input=content,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip() or "unknown git error"
        raise TrustRootError(f"cannot compute Git blob identity for {path}: {detail}")
    git_blob = completed.stdout.decode("ascii", errors="strict").strip().lower()
    if not SHA_PATTERN.fullmatch(git_blob):
        raise TrustRootError(f"Git returned an invalid blob identity for {path}")
    return git_blob, hashlib.sha256(content).hexdigest(), len(content)


def load_protected_manifest(base_root: Path) -> dict[str, str]:
    path = base_root / ".github/trust-root/protected_files.json"
    payload = read_json_object(path)
    if payload.get("schema_version") != MANIFEST_SCHEMA:
        raise TrustRootError("unsupported trust-root protected-files manifest schema")
    files = payload.get("files")
    if not isinstance(files, dict) or not files:
        raise TrustRootError("trust-root protected-files manifest must contain files")

    normalized: dict[str, str] = {}
    for raw_path, raw_digest in files.items():
        if not isinstance(raw_path, str) or not isinstance(raw_digest, str):
            raise TrustRootError("protected file manifest paths and object IDs must be strings")
        posix = PurePosixPath(raw_path)
        if posix.is_absolute() or ".." in posix.parts:
            raise TrustRootError(f"invalid protected file path: {raw_path}")
        digest = raw_digest.strip().lower()
        if not SHA_PATTERN.fullmatch(digest):
            raise TrustRootError(f"invalid Git blob object ID for {raw_path}")
        normalized[raw_path] = digest
    return normalized


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def scan_tree(root: Path) -> dict[str, dict[str, Any]]:
    if not root.is_dir():
        raise TrustRootError(f"repository tree is missing or not a directory: {root}")
    entries: dict[str, dict[str, Any]] = {}
    canonical_paths: set[str] = set()

    def record(path: Path) -> None:
        relative = path.relative_to(root).as_posix()
        if not relative or relative == ".git" or relative.startswith(".git/"):
            return
        if any(ord(character) < 32 for character in relative):
            raise TrustRootError(f"repository path contains a control character: {relative!r}")
        canonical = relative.casefold()
        if canonical in canonical_paths:
            raise TrustRootError(f"case-insensitive duplicate repository path: {relative}")
        canonical_paths.add(canonical)
        if path.is_symlink():
            entries[relative] = {"kind": "symlink", "target": os.readlink(path)}
        elif path.is_file():
            sha256, size = _sha256_file(path)
            entries[relative] = {"kind": "file", "sha256": sha256, "bytes": size}
        else:
            entries[relative] = {"kind": "other"}

    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        retained: list[str] = []
        for dirname in sorted(dirnames):
            candidate = current_path / dirname
            relative = candidate.relative_to(root)
            if relative.parts and relative.parts[0] == ".git":
                continue
            if candidate.is_symlink():
                record(candidate)
            else:
                retained.append(dirname)
        dirnames[:] = retained
        for filename in sorted(filenames):
            candidate = current_path / filename
            relative = candidate.relative_to(root)
            if relative.parts and relative.parts[0] == ".git":
                continue
            record(candidate)
    return entries


def compare_trees(base_root: Path, subject_root: Path) -> tuple[str, ...]:
    base_entries = scan_tree(base_root)
    subject_entries = scan_tree(subject_root)
    return tuple(
        path
        for path in sorted(set(base_entries) | set(subject_entries))
        if base_entries.get(path) != subject_entries.get(path)
    )


def verify_subject(
    *,
    base_root: Path,
    subject_root: Path,
    expected_head: str,
    repository: str,
    pull_number: int,
    run_id: int,
    run_attempt: int,
) -> dict[str, Any]:
    expected = normalize_sha(expected_head, label="expected pull request head")
    repository_name = require_repository(repository)
    pr_number = positive_int(pull_number, label="pull request number")
    normalized_run_id = positive_int(run_id, label="run id")
    normalized_attempt = positive_int(run_attempt, label="run attempt")
    actual = resolve_git_head(subject_root)
    if actual != expected:
        raise TrustRootError(f"subject checkout is stale: expected {expected}, got {actual}")

    protected_files = load_protected_manifest(base_root)
    approved_workflows = {path for path in protected_files if path.startswith(WORKFLOW_PREFIX)}
    changed = compare_trees(base_root, subject_root)
    findings: list[dict[str, str]] = []

    for path in changed:
        if path in PROTECTED_EXACT or any(path.startswith(prefix) for prefix in PROTECTED_PREFIXES):
            findings.append(
                {
                    "code": "CML-TRUST-ROOT-PROTECTED-PATH-CHANGED",
                    "path": path,
                    "message": "protected trust-root files require a dedicated bootstrap review",
                }
            )
        elif path in protected_files:
            continue
        elif path.startswith(WORKFLOW_PREFIX):
            findings.append(
                {
                    "code": "CML-TRUST-ROOT-UNAPPROVED-WORKFLOW-CHANGE",
                    "path": path,
                    "message": "unapproved workflow additions or edits are forbidden",
                }
            )
        else:
            parts = PurePosixPath(path).parts
            root_part = parts[0] if parts else ""
            module_root = root_part.removesuffix(".py")
            is_top_level_path = len(parts) == 1
            introduces_top_level_root = (
                len(parts) > 1 and bool(root_part) and not (base_root / root_part).exists()
            )
            if module_root in DANGEROUS_IMPORT_ROOTS and (
                is_top_level_path or introduces_top_level_root
            ):
                findings.append(
                    {
                        "code": "CML-TRUST-ROOT-IMPORT-SHADOWING",
                        "path": path,
                        "message": "changed top-level path could shadow imports used by protected CI helpers",
                    }
                )

    observed_git_blobs: dict[str, str] = {}
    observed_sha256: dict[str, str] = {}
    observed_bytes: dict[str, int] = {}
    for relative, expected_digest in sorted(protected_files.items()):
        subject_path = subject_root / relative
        try:
            observed, sha256, size = file_identity(subject_path)
        except TrustRootError as exc:
            findings.append(
                {
                    "code": "CML-TRUST-ROOT-PROTECTED-FILE-MISSING",
                    "path": relative,
                    "message": str(exc),
                }
            )
            continue
        observed_git_blobs[relative] = observed
        observed_sha256[relative] = sha256
        observed_bytes[relative] = size
        if observed != expected_digest:
            findings.append(
                {
                    "code": "CML-TRUST-ROOT-PROTECTED-FILE-MISMATCH",
                    "path": relative,
                    "message": f"Git blob object ID {observed} != trusted {expected_digest}",
                }
            )

    findings.sort(key=lambda item: (item["code"], item["path"], item["message"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repository_name,
        "pull_number": pr_number,
        "run_id": normalized_run_id,
        "run_attempt": normalized_attempt,
        "expected_head": expected,
        "actual_head": actual,
        "matched_head": True,
        "approved_files": sorted(protected_files),
        "approved_workflows": sorted(approved_workflows),
        "observed_git_blob_sha1": observed_git_blobs,
        "observed_sha256": observed_sha256,
        "observed_bytes": observed_bytes,
        "changed_file_count": len(changed),
        "changed_files": list(changed),
        "findings": findings,
        "passed": not findings,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_failure_report(
    *,
    repository: str,
    pull_number: int,
    run_id: str | int,
    run_attempt: str | int,
    expected_head: str,
    error: Exception,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "pull_number": pull_number,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "expected_head": expected_head,
        "passed": False,
        "error": {"type": type(error).__name__, "message": str(error)},
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-root", type=Path, required=True)
    parser.add_argument("--subject-root", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-number", type=int, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        result = verify_subject(
            base_root=args.base_root.resolve(),
            subject_root=args.subject_root.resolve(),
            expected_head=args.expected_head,
            repository=args.repository,
            pull_number=args.pull_number,
            run_id=positive_int(args.run_id, label="run id"),
            run_attempt=positive_int(args.run_attempt, label="run attempt"),
        )
    except Exception as exc:
        failure = build_failure_report(
            repository=args.repository,
            pull_number=args.pull_number,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            expected_head=args.expected_head,
            error=exc,
        )
        try:
            write_json(args.output, failure)
        except Exception as write_error:
            raise SystemExit(
                f"CML trust-root verification failed closed: {exc}; "
                f"failure evidence could not be written: {write_error}"
            ) from write_error
        raise SystemExit(f"CML trust-root verification failed closed: {exc}") from exc

    write_json(args.output, result)
    if not result["passed"]:
        summary = "; ".join(
            f"{finding['code']}:{finding['path']}" for finding in result["findings"]
        )
        raise SystemExit(f"CML trust-root verification failed closed: {summary}")
    print(f"CML trust-root verification passed for {result['actual_head']}")


if __name__ == "__main__":
    main()
