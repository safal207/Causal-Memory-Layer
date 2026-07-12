from __future__ import annotations

from pathlib import Path

from scripts.ci.verify_workflow_contract import PINNED_ACTION, verify_workflow, verify_workflows

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = [
    ROOT / ".github/workflows/ci.yml",
    ROOT / ".github/workflows/python-package-validation.yml",
    ROOT / ".github/workflows/security.yml",
]


def test_required_workflows_satisfy_trust_contract():
    report = verify_workflows(WORKFLOWS)
    assert report["passed"] is True, report["violations"]


def test_action_pin_pattern_is_segment_bounded():
    sha = "a" * 40
    assert PINNED_ACTION.fullmatch(f"actions/checkout@{sha}")
    assert PINNED_ACTION.fullmatch(f"github/codeql-action/init@{sha}")
    assert not PINNED_ACTION.fullmatch(f"github/codeql-action//init@{sha}")
    assert not PINNED_ACTION.fullmatch("actions/checkout@v6")


def _mutate(tmp_path: Path, source: Path, old: str, new: str) -> Path:
    mutated = tmp_path / source.name
    original = source.read_text(encoding="utf-8")
    assert old in original
    mutated.write_text(original.replace(old, new, 1), encoding="utf-8")
    return mutated


def test_contract_rejects_mutable_action_tag(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[0],
        "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
        "actions/checkout@v6",
    )
    assert any("not pinned to a full SHA" in item for item in verify_workflow(mutated))


def test_contract_rejects_persisted_checkout_credentials(tmp_path: Path):
    mutated = _mutate(tmp_path, WORKFLOWS[0], "persist-credentials: false", "persist-credentials: true")
    assert any("credentials must not persist" in item for item in verify_workflow(mutated))


def test_contract_rejects_non_exact_checkout(tmp_path: Path):
    mutated = _mutate(tmp_path, WORKFLOWS[0], "ref: ${{ env.EXPECTED_SHA }}", "ref: ${{ github.sha }}")
    assert any("checkout ref is not exact-head bound" in item for item in verify_workflow(mutated))


def test_contract_rejects_missing_artifact_downgrade(tmp_path: Path):
    mutated = _mutate(tmp_path, WORKFLOWS[0], "if-no-files-found: error", "if-no-files-found: warn")
    assert any("missing evidence must be an error" in item for item in verify_workflow(mutated))


def test_contract_rejects_pull_request_target(tmp_path: Path):
    mutated = _mutate(tmp_path, WORKFLOWS[0], "  pull_request:", "  pull_request_target:")
    violations = verify_workflow(mutated)
    assert any("pull_request_target is forbidden" in item for item in violations)


def test_contract_rejects_duplicate_yaml_keys(tmp_path: Path):
    mutated = tmp_path / WORKFLOWS[0].name
    mutated.write_text(
        WORKFLOWS[0].read_text(encoding="utf-8") + "\npermissions: {}\n",
        encoding="utf-8",
    )
    assert any("duplicate key" in item for item in verify_workflow(mutated))
