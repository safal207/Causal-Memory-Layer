from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER_RE = re.compile(r"(?:<[^>]+>|\bTODO\b|\bTBD\b|replace-me)", re.IGNORECASE)
SECRET_MARKERS = (
    "database_url",
    "demo_api_key",
    "password",
    "private_key",
    "secret_access_key",
    "session_token",
    "bearer ",
    "postgresql://",
)

REQUIRED_TEXT_FIELDS = (
    "repository_commit_sha",
    "repository_url",
    "license_url",
    "lambda_function_url",
    "video_url",
    "devpost_submission_url",
    "ccloud_evidence_path",
    "vector_explain_evidence_path",
    "negative_outcome_id",
    "decision_memory_id_after",
    "runtime_instance_id_before",
    "runtime_instance_id_after",
    "retrieval_mode",
    "retrieval_tool",
    "execution_authority",
    "judging_availability_end",
    "testing_instructions",
)


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def _require_file(manifest_path: Path, value: str, field: str, failures: list[str]) -> None:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = (manifest_path.parent / candidate).resolve()
    if not candidate.is_file():
        # Never copy a user-supplied path into diagnostics. A path can contain
        # embedded credentials or other sensitive deployment details.
        failures.append(f"{field} does not point to an existing reviewed file")


def validate_manifest(manifest_path: Path, manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []

    for field in REQUIRED_TEXT_FIELDS:
        value = manifest.get(field)
        if not isinstance(value, str) or not value.strip():
            failures.append(f"missing non-empty field: {field}")
            continue
        if PLACEHOLDER_RE.search(value):
            failures.append(f"placeholder remains in field: {field}")

    sha = str(manifest.get("repository_commit_sha") or "")
    if sha and not SHA_RE.fullmatch(sha):
        failures.append("repository_commit_sha must be a full lowercase 40-character SHA")

    url_rules = {
        "repository_url": ("github.com",),
        "license_url": ("github.com",),
        "lambda_function_url": ("lambda-url", "on.aws"),
        "video_url": ("youtube.com", "youtu.be", "vimeo.com"),
        "devpost_submission_url": ("devpost.com",),
    }
    for field, allowed_fragments in url_rules.items():
        value = str(manifest.get(field) or "")
        if value and not _is_http_url(value):
            failures.append(f"{field} must be a valid HTTPS URL")
        elif value and not any(fragment in urlparse(value).netloc for fragment in allowed_fragments):
            failures.append(f"{field} has an unexpected host")

    for field in ("negative_outcome_id", "decision_memory_id_after"):
        value = str(manifest.get(field) or "")
        if value:
            try:
                uuid.UUID(value)
            except ValueError:
                failures.append(f"{field} must be a valid UUID")

    runtime_before = str(manifest.get("runtime_instance_id_before") or "")
    runtime_after = str(manifest.get("runtime_instance_id_after") or "")
    if runtime_before and runtime_after and runtime_before == runtime_after:
        failures.append("runtime_instance_id_before and runtime_instance_id_after must differ")

    expected_contract = {
        "retrieval_mode": "cockroachdb_vector_cosine",
        "retrieval_tool": "distributed_vector_index",
        "execution_authority": "advisory_only",
    }
    for field, expected in expected_contract.items():
        if manifest.get(field) != expected:
            failures.append(f"{field} must equal {expected}")

    screenshots = manifest.get("screenshots")
    if not isinstance(screenshots, list) or len(screenshots) < 3:
        failures.append("screenshots must contain at least three reviewed evidence files")
    else:
        for index, screenshot in enumerate(screenshots):
            if not isinstance(screenshot, str) or not screenshot:
                failures.append(f"screenshots[{index}] must be a non-empty path")
            else:
                _require_file(manifest_path, screenshot, f"screenshots[{index}]", failures)

    for field in ("ccloud_evidence_path", "vector_explain_evidence_path"):
        value = manifest.get(field)
        if isinstance(value, str) and value and not PLACEHOLDER_RE.search(value):
            _require_file(manifest_path, value, field, failures)

    ccloud_path = manifest.get("ccloud_evidence_path")
    if isinstance(ccloud_path, str) and ccloud_path and not PLACEHOLDER_RE.search(ccloud_path):
        candidate = Path(ccloud_path)
        if not candidate.is_absolute():
            candidate = (manifest_path.parent / candidate).resolve()
        checksum = candidate.with_suffix(candidate.suffix + ".sha256")
        if candidate.is_file() and not checksum.is_file():
            failures.append("ccloud evidence SHA-256 sidecar is missing")

    serialized = json.dumps(manifest, sort_keys=True).casefold()
    for marker in SECRET_MARKERS:
        if marker in serialized:
            failures.append(f"public manifest contains a credential-like marker: {marker}")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail closed unless the final Liminal Recall submission package is complete."
    )
    parser.add_argument("manifest", type=Path, help="Path to final-submission.json")
    parser.add_argument(
        "--report",
        type=Path,
        help="Optional path for a machine-readable validation report",
    )
    args = parser.parse_args()

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: unable to read manifest: {type(exc).__name__}", file=sys.stderr)
        return 2
    if not isinstance(manifest, dict):
        print("ERROR: manifest must be a JSON object", file=sys.stderr)
        return 2

    failures = validate_manifest(args.manifest.resolve(), manifest)
    report = {
        "ready": not failures,
        "failure_count": len(failures),
        "failures": failures,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print("PASS: final submission manifest satisfies all local gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
