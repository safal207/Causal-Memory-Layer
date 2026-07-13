from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.assert_exact_head import ExactHeadError, build_report, write_json_atomic
from scripts.ci.build_evidence_manifest import EvidenceError, build_manifest

SHA = "a" * 40


def manifest_for(root: Path, *, output: Path | None = None, required=()):
    return build_manifest(
        artifacts_root=root,
        repository="safal207/Causal-Memory-Layer",
        source_repository="safal207/Causal-Memory-Layer",
        tested_sha=SHA,
        event_name="pull_request",
        run_id="123",
        run_attempt="2",
        change_number="166",
        workflow_ref="safal207/Causal-Memory-Layer/.github/workflows/ci.yml@refs/pull/166/merge",
        required_patterns=required,
        output_path=output,
    )


def test_exact_head_report_rejects_mismatch_and_short_sha():
    assert build_report(expected_sha=SHA.upper(), actual_sha=SHA)["matched"] is True
    with pytest.raises(ExactHeadError, match="not exact-head bound"):
        build_report(expected_sha=SHA, actual_sha="b" * 40)
    with pytest.raises(ExactHeadError, match="40-character"):
        build_report(expected_sha="abc", actual_sha=SHA)


def test_evidence_manifest_is_sorted_hashed_and_deterministic(tmp_path: Path):
    root = tmp_path / "evidence"
    (root / "lane-b").mkdir(parents=True)
    (root / "lane-a").mkdir()
    (root / "lane-b" / "report.json").write_text('{"ok":true}\n', encoding="utf-8")
    (root / "lane-a" / "coverage.xml").write_text("<coverage/>\n", encoding="utf-8")
    write_json_atomic(root / "lane-a" / "exact-head.json", build_report(expected_sha=SHA, actual_sha=SHA))

    first = manifest_for(root, required=("lane-a/coverage.xml", "**/report.json"))
    second = manifest_for(root, required=("lane-a/coverage.xml", "**/report.json"))

    assert first == second
    assert first["artifact_count"] == 3
    assert [item["path"] for item in first["artifacts"]] == [
        "lane-a/coverage.xml",
        "lane-a/exact-head.json",
        "lane-b/report.json",
    ]
    assert all(len(item["sha256"]) == 64 for item in first["artifacts"])


def test_evidence_manifest_fails_on_missing_required_file(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "present.json").write_text("{}\n", encoding="utf-8")
    write_json_atomic(root / "exact-head.json", build_report(expected_sha=SHA, actual_sha=SHA))
    with pytest.raises(EvidenceError, match="matched no files"):
        manifest_for(root, required=("missing/*.xml",))


def test_evidence_manifest_rejects_directory_for_required_file(tmp_path: Path):
    root = tmp_path / "evidence"
    (root / "lane-a" / "coverage.xml").mkdir(parents=True)
    write_json_atomic(root / "exact-head.json", build_report(expected_sha=SHA, actual_sha=SHA))

    with pytest.raises(EvidenceError, match="matched no files eligible for hashing"):
        manifest_for(root, required=("lane-a/coverage.xml",))


def test_evidence_manifest_rejects_symlinks(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("secret", encoding="utf-8")
    (root / "link.txt").symlink_to(target)
    write_json_atomic(root / "exact-head.json", build_report(expected_sha=SHA, actual_sha=SHA))
    with pytest.raises(EvidenceError, match="symbolic links"):
        manifest_for(root)


def test_existing_output_inside_root_is_not_self_hashed(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "report.json").write_text("{}\n", encoding="utf-8")
    write_json_atomic(root / "exact-head.json", build_report(expected_sha=SHA, actual_sha=SHA))
    output = root / "manifest.json"
    write_json_atomic(output, {"old": True})

    manifest = manifest_for(root, output=output)
    assert [item["path"] for item in manifest["artifacts"]] == [
        "exact-head.json",
        "report.json",
    ]

    write_json_atomic(output, manifest)
    assert json.loads(output.read_text(encoding="utf-8")) == manifest


def test_evidence_manifest_rejects_stale_bound_json(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    write_json_atomic(root / "exact-head.json", build_report(expected_sha=SHA, actual_sha=SHA))
    write_json_atomic(
        root / "gate-results.json",
        {"schema_version": "example", "tested_sha": "b" * 40},
    )
    with pytest.raises(EvidenceError, match="stale JSON evidence"):
        manifest_for(root)


def test_evidence_manifest_requires_exact_head_report(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "report.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(EvidenceError, match="no exact-head report"):
        manifest_for(root)


def test_evidence_manifest_rejects_escaping_required_pattern(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    write_json_atomic(root / "exact-head.json", build_report(expected_sha=SHA, actual_sha=SHA))
    with pytest.raises(EvidenceError, match="escapes the artifacts root"):
        manifest_for(root, required=("../outside.json",))


def test_evidence_manifest_rejects_duplicate_json_keys(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    write_json_atomic(root / "exact-head.json", build_report(expected_sha=SHA, actual_sha=SHA))
    (root / "ambiguous.json").write_text('{"passed":true,"passed":false}\n', encoding="utf-8")
    with pytest.raises(EvidenceError, match="duplicate JSON key"):
        manifest_for(root)
