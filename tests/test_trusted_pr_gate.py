from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / ".github/trust-root/scripts/verify_subject.py"
SPEC = importlib.util.spec_from_file_location("verify_subject", MODULE_PATH)
assert SPEC and SPEC.loader
verify_subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_subject)

WORKFLOWS = (
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    ".github/workflows/python-package-validation.yml",
)


def git_blob_id(content: bytes) -> str:
    completed = subprocess.run(
        ["git", "hash-object", "--stdin"],
        input=content,
        check=True,
        capture_output=True,
    )
    return completed.stdout.decode("ascii").strip()


def write_common_tree(root: Path, hashes: dict[str, str] | None = None) -> dict[str, str]:
    result = {} if hashes is None else dict(hashes)
    for index, relative in enumerate(WORKFLOWS):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        content = f"name: workflow-{index}\n".encode()
        path.write_bytes(content)
        result.setdefault(relative, git_blob_id(content))
    manifest = root / ".github/trust-root/protected_files.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps({"schema_version": "cml-trust-root-files-v1", "files": result}),
        encoding="utf-8",
    )
    gate = root / ".github/workflows/trusted-pr-gate.yml"
    gate.write_text("name: trusted\n", encoding="utf-8")
    return result


def build_fixture(tmp_path: Path) -> tuple[Path, Path]:
    base = tmp_path / "base"
    subject = tmp_path / "subject"
    hashes = write_common_tree(base)
    write_common_tree(subject, hashes)
    return base, subject


def commit_subject(subject: Path) -> str:
    subprocess.run(["git", "init"], cwd=subject, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=subject, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=subject, check=True)
    subprocess.run(["git", "add", "."], cwd=subject, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=subject, check=True, capture_output=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=subject,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def verify(base: Path, subject: Path, head: str):
    return verify_subject.verify_subject(
        base_root=base,
        subject_root=subject,
        expected_head=head,
        repository="safal207/Causal-Memory-Layer",
        pull_number=169,
        run_id=123,
        run_attempt=2,
    )


def test_valid_subject_passes(tmp_path: Path):
    base, subject = build_fixture(tmp_path)
    path = subject / "cml/core.py"
    path.parent.mkdir(parents=True)
    path.write_text("VALUE = 1\n", encoding="utf-8")
    result = verify(base, subject, commit_subject(subject))
    assert result["passed"] is True
    assert result["run_attempt"] == 2
    assert result["changed_files"] == ["cml/core.py"]


def test_protected_file_mismatch_fails(tmp_path: Path):
    base, subject = build_fixture(tmp_path)
    (subject / WORKFLOWS[0]).write_text("name: weakened\n", encoding="utf-8")
    result = verify(base, subject, commit_subject(subject))
    assert result["passed"] is False
    assert {item["code"] for item in result["findings"]} == {
        "CML-TRUST-ROOT-PROTECTED-FILE-MISMATCH"
    }


def test_unapproved_workflow_is_rejected(tmp_path: Path):
    base, subject = build_fixture(tmp_path)
    (subject / ".github/workflows/spoof-status.yml").write_text("name: spoof\n", encoding="utf-8")
    result = verify(base, subject, commit_subject(subject))
    assert result["passed"] is False
    assert result["findings"][0]["code"] == "CML-TRUST-ROOT-UNAPPROVED-WORKFLOW-CHANGE"


def test_protected_trust_root_change_is_rejected(tmp_path: Path):
    base, subject = build_fixture(tmp_path)
    manifest = subject / ".github/trust-root/protected_files.json"
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    result = verify(base, subject, commit_subject(subject))
    assert result["passed"] is False
    assert result["findings"][0]["code"] == "CML-TRUST-ROOT-PROTECTED-PATH-CHANGED"


def test_stale_subject_head_is_rejected(tmp_path: Path):
    base, subject = build_fixture(tmp_path)
    commit_subject(subject)
    with pytest.raises(verify_subject.TrustRootError, match="stale"):
        verify(base, subject, "a" * 40)


def test_duplicate_manifest_key_is_rejected(tmp_path: Path):
    base, subject = build_fixture(tmp_path)
    manifest = base / ".github/trust-root/protected_files.json"
    manifest.write_text(
        '{"schema_version":"x","schema_version":"y","files":{}}',
        encoding="utf-8",
    )
    head = commit_subject(subject)
    with pytest.raises(verify_subject.TrustRootError, match="duplicate JSON key"):
        verify(base, subject, head)


def test_import_shadowing_path_is_rejected(tmp_path: Path):
    base, subject = build_fixture(tmp_path)
    (subject / "json.py").write_text("raise RuntimeError\n", encoding="utf-8")
    result = verify(base, subject, commit_subject(subject))
    assert result["passed"] is False
    assert result["findings"][0]["code"] == "CML-TRUST-ROOT-IMPORT-SHADOWING"


def test_renamed_protected_path_is_detected_without_api(tmp_path: Path):
    base, subject = build_fixture(tmp_path)
    source = subject / ".github/workflows/trusted-pr-gate.yml"
    target = subject / "docs/renamed.yml"
    target.parent.mkdir(parents=True)
    source.rename(target)
    changed = verify_subject.compare_trees(base, subject)
    assert ".github/workflows/trusted-pr-gate.yml" in changed
    assert "docs/renamed.yml" in changed


def test_tree_comparison_has_no_3000_file_cap(tmp_path: Path):
    base = tmp_path / "base"
    subject = tmp_path / "subject"
    base.mkdir()
    subject.mkdir()
    data = subject / "data"
    data.mkdir()
    for index in range(3001):
        (data / f"{index:04d}.txt").write_text(str(index), encoding="utf-8")
    changed = verify_subject.compare_trees(base, subject)
    assert len(changed) == 3001
    assert "data/3000.txt" in changed


def test_main_writes_failure_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    base, subject = build_fixture(tmp_path)
    commit_subject(subject)
    output = tmp_path / "failure.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_subject.py",
            "--base-root",
            str(base),
            "--subject-root",
            str(subject),
            "--expected-head",
            "a" * 40,
            "--repository",
            "safal207/Causal-Memory-Layer",
            "--pull-number",
            "169",
            "--run-id",
            "123",
            "--run-attempt",
            "2",
            "--output",
            str(output),
        ],
    )
    with pytest.raises(SystemExit):
        verify_subject.main()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["passed"] is False
    assert payload["run_attempt"] == "2"
    assert payload["error"]["type"] == "TrustRootError"


def test_repository_manifest_matches_exact_tree():
    protected = verify_subject.load_protected_manifest(ROOT)
    assert protected
    for relative, expected_blob in protected.items():
        actual_blob, sha256, size = verify_subject.file_identity(ROOT / relative)
        assert actual_blob == expected_blob, relative
        assert len(sha256) == 64
        assert size > 0
