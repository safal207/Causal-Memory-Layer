"""Resolve security-lane evidence across selective GitHub Actions reruns.

A workflow run has one stable run_id, while github.run_attempt increments for
partial reruns. Jobs that were not rerun keep evidence from an earlier attempt.
This helper selects the newest available artifact for each protected lane within
the same run_id and verifies that evidence before copying it into a stable
manifest input path.

Fail-closed rule: if a newer artifact exists for a lane, it must validate. The
resolver never falls back past malformed, stale, or failed newer evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
ARTIFACT_PATTERN = re.compile(
    r"^cml-security-lane-(dependency|secret|codeql)-([1-9][0-9]*)-([1-9][0-9]*)$"
)

LANES = {
    "dependency": ("scanner-results.json", "cml-security-scan-results-v1"),
    "secret": ("gitleaks.json", "cml-gitleaks-result-v1"),
    "codeql": ("codeql.json", "cml-codeql-result-v1"),
}

SCHEMA_VERSION = "cml-security-evidence-selection-v1"


class SecurityEvidenceError(ValueError):
    """Raised when exact-run security evidence cannot be established."""


def _positive_int(value: int | str, *, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise SecurityEvidenceError(f"{label} must be an integer") from exc
    if parsed < 1:
        raise SecurityEvidenceError(f"{label} must be >= 1")
    return parsed


def _tested_sha(value: str) -> str:
    normalized = value.strip().lower()
    if not SHA_PATTERN.fullmatch(normalized):
        raise SecurityEvidenceError("tested_sha must be a full lowercase Git SHA")
    return normalized


def _read_json_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SecurityEvidenceError(f"evidence must be a regular file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityEvidenceError(f"cannot read evidence {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SecurityEvidenceError(f"evidence must be a JSON object: {path}")
    return payload


def _sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _candidate_dirs(collected_root: Path, *, lane: str, run_id: int) -> list[tuple[int, Path]]:
    candidates: list[tuple[int, Path]] = []
    if not collected_root.is_dir():
        raise SecurityEvidenceError(f"collected evidence root is missing: {collected_root}")

    for child in collected_root.iterdir():
        if child.is_symlink() or not child.is_dir():
            continue
        match = ARTIFACT_PATTERN.fullmatch(child.name)
        if match is None:
            continue
        candidate_lane, raw_run_id, raw_attempt = match.groups()
        if candidate_lane != lane or int(raw_run_id) != run_id:
            continue
        candidates.append((int(raw_attempt), child))

    return sorted(candidates, key=lambda item: item[0], reverse=True)


def resolve_security_evidence(
    *,
    collected_root: Path,
    run_id: int | str,
    tested_sha: str,
    output_root: Path,
) -> dict[str, Any]:
    normalized_run_id = _positive_int(run_id, label="run_id")
    normalized_sha = _tested_sha(tested_sha)

    resolved: dict[str, Any] = {}
    output_root.mkdir(parents=True, exist_ok=True)

    for lane, (filename, expected_schema) in LANES.items():
        candidates = _candidate_dirs(
            collected_root,
            lane=lane,
            run_id=normalized_run_id,
        )
        if not candidates:
            raise SecurityEvidenceError(
                f"no evidence artifact for lane={lane} run_id={normalized_run_id}"
            )

        attempt, artifact_dir = candidates[0]
        source = artifact_dir / filename
        payload = _read_json_object(source)

        if payload.get("schema_version") != expected_schema:
            raise SecurityEvidenceError(
                f"lane={lane} attempt={attempt} has unexpected schema"
            )
        if payload.get("tested_sha") != normalized_sha:
            raise SecurityEvidenceError(
                f"lane={lane} attempt={attempt} tested_sha mismatch"
            )
        if payload.get("passed") is not True:
            raise SecurityEvidenceError(
                f"lane={lane} attempt={attempt} is not passing evidence"
            )

        destination_dir = output_root / lane
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination = destination_dir / filename
        shutil.copyfile(source, destination)

        digest, size = _sha256(destination)
        resolved[lane] = {
            "artifact_name": artifact_dir.name,
            "run_attempt": attempt,
            "evidence_path": destination.relative_to(output_root.parent).as_posix(),
            "sha256": digest,
            "bytes": size,
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": normalized_run_id,
        "tested_sha": normalized_sha,
        "lanes": resolved,
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collected-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tested-sha", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--selection-output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        result = resolve_security_evidence(
            collected_root=args.collected_root,
            run_id=args.run_id,
            tested_sha=args.tested_sha,
            output_root=args.output_root,
        )
    except Exception as exc:
        raise SystemExit(f"security evidence resolution failed closed: {exc}") from exc

    _write_json(args.selection_output, result)
    print(
        "Resolved security evidence: "
        + ", ".join(
            f"{lane}=attempt-{details['run_attempt']}"
            for lane, details in sorted(result["lanes"].items())
        )
    )


if __name__ == "__main__":
    main()
