from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_SIDECAR_RE = re.compile(
    r"^(?P<digest>[0-9a-f]{64})  (?P<filename>[^/\\\s]+)$"
)
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
    "deployed_build_sha",
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


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_json_object,
    )
    if not isinstance(payload, dict):
        raise ValueError("manifest must be a JSON object")
    return payload


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and port in {None, 443}
    )


def _has_expected_host(field: str, value: str) -> bool:
    host = (urlparse(value).hostname or "").casefold()
    if field in {"repository_url", "license_url"}:
        return host == "github.com"
    if field == "lambda_function_url":
        return bool(
            re.fullmatch(r"[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws", host)
        )
    if field == "video_url":
        return host in {
            "youtube.com",
            "www.youtube.com",
            "youtu.be",
            "vimeo.com",
            "www.vimeo.com",
        }
    if field == "devpost_submission_url":
        return host == "devpost.com" or host.endswith(".devpost.com")
    return False


def _git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    head = completed.stdout.strip()
    if not SHA_RE.fullmatch(head):
        raise RuntimeError("git did not return a full lowercase commit SHA")
    return head


def _resolve_evidence_file(manifest_path: Path, value: str) -> Path | None:
    evidence_root = manifest_path.parent.resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = evidence_root / candidate
    candidate = candidate.resolve()
    if not candidate.is_relative_to(evidence_root):
        return None
    return candidate


def _require_file(manifest_path: Path, value: str, field: str, failures: list[str]) -> None:
    candidate = _resolve_evidence_file(manifest_path, value)
    if candidate is None or not candidate.is_file():
        # Never copy a user-supplied path into diagnostics. A path can contain
        # embedded credentials or other sensitive deployment details.
        failures.append(f"{field} does not point to an existing reviewed file")


def _url_references_sha(value: str, sha: str) -> bool:
    return sha in {segment for segment in urlparse(value).path.split("/") if segment}


def _verify_ccloud_checksum(candidate: Path, failures: list[str]) -> None:
    checksum = candidate.with_suffix(candidate.suffix + ".sha256")
    if not checksum.is_file():
        failures.append("ccloud evidence SHA-256 sidecar is missing")
        return
    try:
        sidecar = checksum.read_text(encoding="utf-8").strip()
        match = SHA256_SIDECAR_RE.fullmatch(sidecar)
        if match is None:
            failures.append("ccloud evidence SHA-256 sidecar is malformed")
            return
        if match.group("filename") != candidate.name:
            failures.append("ccloud evidence SHA-256 sidecar filename does not match")
            return
        actual_digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    except OSError:
        failures.append("ccloud evidence SHA-256 sidecar could not be verified")
        return
    if match.group("digest") != actual_digest:
        failures.append("ccloud evidence SHA-256 sidecar does not match file contents")


def validate_manifest(
    manifest_path: Path,
    manifest: dict[str, Any],
    *,
    reviewed_commit_sha: str | None = None,
) -> list[str]:
    failures: list[str] = []

    for field in REQUIRED_TEXT_FIELDS:
        value = manifest.get(field)
        if not isinstance(value, str) or not value.strip():
            failures.append(f"missing non-empty field: {field}")
            continue
        if PLACEHOLDER_RE.search(value):
            failures.append(f"placeholder remains in field: {field}")

    sha = str(manifest.get("repository_commit_sha") or "")
    deployed_sha = str(manifest.get("deployed_build_sha") or "")
    if sha and not SHA_RE.fullmatch(sha):
        failures.append("repository_commit_sha must be a full lowercase 40-character SHA")
    if deployed_sha and not SHA_RE.fullmatch(deployed_sha):
        failures.append("deployed_build_sha must be a full lowercase 40-character SHA")
    if SHA_RE.fullmatch(sha):
        try:
            actual_sha = reviewed_commit_sha or _git_head()
        except (OSError, RuntimeError, subprocess.SubprocessError):
            failures.append("reviewed repository commit SHA could not be determined")
        else:
            if not SHA_RE.fullmatch(actual_sha) or sha != actual_sha:
                failures.append("repository_commit_sha does not match the reviewed commit HEAD")
        if deployed_sha != sha:
            failures.append("deployed_build_sha does not match repository_commit_sha")

    url_fields = (
        "repository_url",
        "license_url",
        "lambda_function_url",
        "video_url",
        "devpost_submission_url",
    )
    for field in url_fields:
        value = str(manifest.get(field) or "")
        if value and not _is_http_url(value):
            failures.append(f"{field} must be a valid HTTPS URL")
        elif value and not _has_expected_host(field, value):
            failures.append(f"{field} has an unexpected host")

    if SHA_RE.fullmatch(sha):
        for field in ("repository_url", "license_url"):
            value = str(manifest.get(field) or "")
            if value and _is_http_url(value) and not _url_references_sha(value, sha):
                failures.append(f"{field} must reference repository_commit_sha")

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
        candidate = _resolve_evidence_file(manifest_path, ccloud_path)
        if candidate is not None and candidate.is_file():
            _verify_ccloud_checksum(candidate, failures)

    serialized = json.dumps(manifest, sort_keys=True).casefold()
    for marker in SECRET_MARKERS:
        if marker in serialized:
            failures.append("public manifest contains a credential-like marker")
            break

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
        manifest = _load_json_object(args.manifest)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: unable to read manifest: {type(exc).__name__}", file=sys.stderr)
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
