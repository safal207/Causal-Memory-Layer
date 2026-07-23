from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "hackathons"
    / "liminal-recall"
    / "scripts"
    / "submission_gate.py"
)
SPEC = importlib.util.spec_from_file_location("liminal_recall_submission_gate", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def complete_manifest(tmp_path: Path) -> tuple[Path, dict]:
    for name in (
        "ccloud-evidence.json",
        "ccloud-evidence.json.sha256",
        "vector-explain.txt",
        "vector-index.png",
        "semantic-decision.png",
        "restart-proof.png",
    ):
        (tmp_path / name).write_text("reviewed evidence\n", encoding="utf-8")

    manifest_path = tmp_path / "final-submission.json"
    manifest = {
        "repository_commit_sha": "a" * 40,
        "repository_url": "https://github.com/safal207/Causal-Memory-Layer/tree/" + "a" * 40,
        "license_url": "https://github.com/safal207/Causal-Memory-Layer/blob/" + "a" * 40 + "/LICENSE",
        "lambda_function_url": "https://example.lambda-url.us-east-1.on.aws",
        "video_url": "https://youtu.be/example123",
        "devpost_submission_url": "https://devpost.com/software/liminal-recall",
        "ccloud_evidence_path": "ccloud-evidence.json",
        "vector_explain_evidence_path": "vector-explain.txt",
        "negative_outcome_id": str(uuid.uuid4()),
        "decision_memory_id_after": str(uuid.uuid4()),
        "runtime_instance_id_before": str(uuid.uuid4()),
        "runtime_instance_id_after": str(uuid.uuid4()),
        "retrieval_mode": "cockroachdb_vector_cosine",
        "retrieval_tool": "distributed_vector_index",
        "execution_authority": "advisory_only",
        "judging_availability_end": "2026-09-15T17:00:00-04:00",
        "testing_instructions": "Use the private Devpost credential and follow the documented requests.",
        "screenshots": [
            "vector-index.png",
            "semantic-decision.png",
            "restart-proof.png",
        ],
    }
    return manifest_path, manifest


def test_complete_manifest_passes(tmp_path: Path) -> None:
    manifest_path, manifest = complete_manifest(tmp_path)

    assert MODULE.validate_manifest(manifest_path, manifest) == []


def test_equal_runtime_ids_fail_persistence_gate(tmp_path: Path) -> None:
    manifest_path, manifest = complete_manifest(tmp_path)
    manifest["runtime_instance_id_after"] = manifest["runtime_instance_id_before"]

    failures = MODULE.validate_manifest(manifest_path, manifest)

    assert any("must differ" in failure for failure in failures)


def test_placeholders_and_missing_evidence_fail_closed(tmp_path: Path) -> None:
    manifest_path, manifest = complete_manifest(tmp_path)
    manifest["video_url"] = "https://youtube.com/watch?v=<video-id>"
    manifest["vector_explain_evidence_path"] = "missing.txt"

    failures = MODULE.validate_manifest(manifest_path, manifest)

    assert any("placeholder remains" in failure for failure in failures)
    assert any("does not point to an existing reviewed file" in failure for failure in failures)


def test_missing_file_diagnostic_does_not_echo_sensitive_path(tmp_path: Path) -> None:
    manifest_path, manifest = complete_manifest(tmp_path)
    secret_path = "postgresql://user:password@example.test/private-evidence.txt"
    manifest["vector_explain_evidence_path"] = secret_path

    failures = MODULE.validate_manifest(manifest_path, manifest)
    diagnostics = "\n".join(failures)

    assert failures
    assert secret_path not in diagnostics
    assert "user:password@example.test" not in diagnostics
    assert "private-evidence.txt" not in diagnostics


def test_public_manifest_rejects_credential_markers(tmp_path: Path) -> None:
    manifest_path, manifest = complete_manifest(tmp_path)
    manifest["testing_instructions"] = "DATABASE_URL=postgresql://user:pass@example.test/db"

    failures = MODULE.validate_manifest(manifest_path, manifest)

    assert any("credential-like marker" in failure for failure in failures)
