from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / ".github/trust-root/scripts/verify_subject.py"
SPEC = importlib.util.spec_from_file_location("verify_subject", MODULE_PATH)
assert SPEC and SPEC.loader
verify_subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_subject)

WORKFLOWS = (
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    ".github/workflows/python-package-validation.yml",
)


def init_subject(root: Path) -> str:
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=root, check=True, capture_output=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def git_blob_id(content: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(content)).encode() + b"\0" + content,
        usedforsecurity=False,
    ).hexdigest()


def build_fixture(tmp_path: Path):
    trusted = tmp_path / "trusted"
    subject = tmp_path / "subject"
    manifest = trusted / ".github/trust-root/protected_files.json"
    manifest.parent.mkdir(parents=True)
    hashes = {}
    for index, relative in enumerate(WORKFLOWS):
        path = subject / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        content = f"name: workflow-{index}\n".encode()
        path.write_bytes(content)
        hashes[relative] = git_blob_id(content)
    manifest.write_text(
        json.dumps({"schema_version": "cml-trust-root-files-v1", "files": hashes}),
        encoding="utf-8",
    )
    return trusted, subject, init_subject(subject)


def test_valid_subject_passes(tmp_path: Path):
    trusted, subject, head = build_fixture(tmp_path)
    result = verify_subject.verify_subject(
        trusted_root=trusted,
        subject_root=subject,
        expected_head=head,
        changed_files=("cml/core.py",),
    )
    assert result["passed"] is True
    assert result["findings"] == []


def test_protected_file_mismatch_fails(tmp_path: Path):
    trusted, subject, head = build_fixture(tmp_path)
    (subject / WORKFLOWS[0]).write_text("name: weakened\n", encoding="utf-8")
    result = verify_subject.verify_subject(
        trusted_root=trusted,
        subject_root=subject,
        expected_head=head,
        changed_files=(WORKFLOWS[0],),
    )
    assert result["passed"] is False
    assert {item["code"] for item in result["findings"]} == {
        "CML-TRUST-ROOT-PROTECTED-FILE-MISMATCH"
    }


def test_unapproved_workflow_is_rejected(tmp_path: Path):
    trusted, subject, head = build_fixture(tmp_path)
    result = verify_subject.verify_subject(
        trusted_root=trusted,
        subject_root=subject,
        expected_head=head,
        changed_files=(".github/workflows/spoof-status.yml",),
    )
    assert result["passed"] is False
    assert result["findings"][0]["code"] == "CML-TRUST-ROOT-UNAPPROVED-WORKFLOW-CHANGE"


def test_protected_trust_root_change_is_rejected(tmp_path: Path):
    trusted, subject, head = build_fixture(tmp_path)
    result = verify_subject.verify_subject(
        trusted_root=trusted,
        subject_root=subject,
        expected_head=head,
        changed_files=(".github/trust-root/protected_files.json",),
    )
    assert result["passed"] is False
    assert result["findings"][0]["code"] == "CML-TRUST-ROOT-PROTECTED-PATH-CHANGED"


def test_stale_subject_head_is_rejected(tmp_path: Path):
    trusted, subject, _ = build_fixture(tmp_path)
    with pytest.raises(verify_subject.TrustRootError, match="stale"):
        verify_subject.verify_subject(
            trusted_root=trusted,
            subject_root=subject,
            expected_head="a" * 40,
            changed_files=(),
        )


def test_duplicate_manifest_key_is_rejected(tmp_path: Path):
    trusted, _, _ = build_fixture(tmp_path)
    manifest = trusted / ".github/trust-root/protected_files.json"
    manifest.write_text(
        '{"schema_version":"x","schema_version":"y","files":{}}',
        encoding="utf-8",
    )
    with pytest.raises(verify_subject.TrustRootError, match="duplicate JSON key"):
        verify_subject.load_protected_manifest(trusted)


def test_import_shadowing_path_is_rejected(tmp_path: Path):
    trusted, subject, head = build_fixture(tmp_path)
    result = verify_subject.verify_subject(
        trusted_root=trusted,
        subject_root=subject,
        expected_head=head,
        changed_files=("json.py",),
    )
    assert result["passed"] is False
    assert result["findings"][0]["code"] == "CML-TRUST-ROOT-IMPORT-SHADOWING"


def test_approved_script_change_is_identity_checked_not_shadow_rejected(tmp_path: Path):
    trusted, subject, head = build_fixture(tmp_path)
    relative = "scripts/ci/build_evidence_manifest.py"
    content = b"print('trusted')\n"
    path = subject / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    manifest = trusted / ".github/trust-root/protected_files.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["files"][relative] = git_blob_id(content)
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    result = verify_subject.verify_subject(
        trusted_root=trusted,
        subject_root=subject,
        expected_head=head,
        changed_files=(relative,),
    )
    assert result["passed"] is True


def test_renamed_protected_previous_filename_is_exposed():
    paths = verify_subject.changed_paths_from_api_items(
        [
            {
                "filename": "docs/renamed.yml",
                "previous_filename": ".github/workflows/trusted-pr-gate.yml",
            }
        ]
    )
    assert paths == (
        "docs/renamed.yml",
        ".github/workflows/trusted-pr-gate.yml",
    )
