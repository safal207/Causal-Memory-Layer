#!/usr/bin/env python3
"""Verify that a pull request preserves the protected CML CI trust contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SCHEMA_VERSION = "cml-trust-root-verification-v1"
MANIFEST_SCHEMA = "cml-trust-root-files-v1"
PROTECTED_EXACT = {".github/workflows/trusted-pr-gate.yml"}
PROTECTED_PREFIXES = (".github/trust-root/",)
WORKFLOW_PREFIX = ".github/workflows/"
DANGEROUS_IMPORT_ROOTS = {
    "argparse",
    "collections",
    "dataclasses",
    "hashlib",
    "json",
    "os",
    "pathlib",
    "re",
    "scripts",
    "sitecustomize",
    "subprocess",
    "tempfile",
    "typing",
    "urllib",
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
    git_blob = hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content,
        usedforsecurity=False,
    ).hexdigest()
    return git_blob, hashlib.sha256(content).hexdigest(), len(content)


def load_protected_manifest(trusted_root: Path) -> dict[str, str]:
    path = trusted_root / ".github/trust-root/protected_files.json"
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
        if not re.fullmatch(r"[0-9a-f]{40}", digest):
            raise TrustRootError(f"invalid Git blob object ID for {raw_path}")
        normalized[raw_path] = digest
    return normalized


def fetch_changed_files(*, repository: str, pull_number: int, token: str) -> tuple[str, ...]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise TrustRootError("repository has an invalid format")
    if pull_number <= 0:
        raise TrustRootError("pull request number must be positive")
    if not token:
        raise TrustRootError("GitHub token is required to read pull request files")

    changed: list[str] = []
    page = 1
    while True:
        query = urllib.parse.urlencode({"per_page": 100, "page": page})
        url = f"https://api.github.com/repos/{repository}/pulls/{pull_number}/files?{query}"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "cml-trust-root-gate",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except Exception as exc:
            raise TrustRootError(f"cannot read pull request file list: {exc}") from exc
        if not isinstance(payload, list):
            raise TrustRootError("GitHub pull request files response must be a list")
        for item in payload:
            if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
                raise TrustRootError("GitHub pull request files response is malformed")
            changed.append(item["filename"])
        if len(payload) < 100:
            break
        page += 1
        if page > 100:
            raise TrustRootError("pull request file list exceeds bounded pagination")
    return tuple(changed)


def verify_subject(
    *,
    trusted_root: Path,
    subject_root: Path,
    expected_head: str,
    changed_files: Iterable[str],
) -> dict[str, Any]:
    expected = normalize_sha(expected_head, label="expected pull request head")
    actual = resolve_git_head(subject_root)
    if actual != expected:
        raise TrustRootError(f"subject checkout is stale: expected {expected}, got {actual}")

    protected_files = load_protected_manifest(trusted_root)
    approved_workflows = {path for path in protected_files if path.startswith(WORKFLOW_PREFIX)}
    changed = tuple(sorted(set(changed_files)))
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
        elif path.startswith(WORKFLOW_PREFIX) and path not in approved_workflows:
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
            if module_root in DANGEROUS_IMPORT_ROOTS:
                findings.append(
                    {
                        "code": "CML-TRUST-ROOT-IMPORT-SHADOWING",
                        "path": path,
                        "message": "changed root path could shadow modules used by trusted CI helpers",
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
        "expected_head": expected,
        "actual_head": actual,
        "matched_head": True,
        "approved_files": sorted(protected_files),
        "approved_workflows": sorted(approved_workflows),
        "observed_git_blob_sha1": observed_git_blobs,
        "observed_sha256": observed_sha256,
        "observed_bytes": observed_bytes,
        "changed_files": list(changed),
        "findings": findings,
        "passed": not findings,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-root", type=Path, required=True)
    parser.add_argument("--subject-root", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-number", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--changed-files-json",
        type=Path,
        help="Optional test input; production reads changed files from GitHub",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        if args.changed_files_json is not None:
            payload = read_json_object(args.changed_files_json)
            raw_changed = payload.get("changed_files")
            if not isinstance(raw_changed, list) or not all(isinstance(item, str) for item in raw_changed):
                raise TrustRootError("changed-files JSON must contain a string list")
            changed_files = tuple(raw_changed)
        else:
            changed_files = fetch_changed_files(
                repository=args.repository,
                pull_number=args.pull_number,
                token=os.environ.get("GITHUB_TOKEN", ""),
            )
        result = verify_subject(
            trusted_root=args.trusted_root.resolve(),
            subject_root=args.subject_root.resolve(),
            expected_head=args.expected_head,
            changed_files=changed_files,
        )
        write_json(args.output, result)
        if not result["passed"]:
            raise TrustRootError(
                "; ".join(
                    f"{finding['code']}:{finding['path']}" for finding in result["findings"]
                )
            )
    except TrustRootError as exc:
        raise SystemExit(f"CML trust-root verification failed closed: {exc}") from exc
    print(f"CML trust-root verification passed for {result['actual_head']}")


if __name__ == "__main__":
    main()
