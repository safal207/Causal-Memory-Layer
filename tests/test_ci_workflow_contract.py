from __future__ import annotations

import shlex
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from scripts.ci.verify_workflow_contract import (
    PINNED_ACTION,
    UniqueKeyLoader,
    verify_workflow,
    verify_workflows,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = [
    ROOT / ".github/workflows/ci.yml",
    ROOT / ".github/workflows/python-package-validation.yml",
    ROOT / ".github/workflows/security.yml",
    ROOT / ".github/workflows/causal-pr.yml",
]
CAUSAL_REQUIRED_TYPES = {
    "edited",
    "opened",
    "ready_for_review",
    "reopened",
    "synchronize",
}
EXPECTED_SHA_EXPRESSION = "${{ github.event.pull_request.head.sha || github.sha }}"
SHALLOW_FETCH_OPTIONS = (
    "--deepen",
    "--depth",
    "--shallow-exclude",
    "--shallow-since",
)
CRITICAL_STEP_NAMES = (
    "Fetch exact base commit",
    "Reconfirm base tip before evidence",
    "Reconfirm base tip before final manifest",
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _uses_shallow_fetch_option(script: str) -> bool:
    try:
        tokens = shlex.split(script, comments=True, posix=True)
    except ValueError:
        return True
    return any(
        token == option or token.startswith(f"{option}=")
        for token in tokens
        for option in SHALLOW_FETCH_OPTIONS
    )


def _causal_contract_violations(path: Path) -> list[str]:
    workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    assert isinstance(workflow, dict)
    violations: list[str] = []

    triggers = _mapping(workflow.get("on"))
    pull_request = _mapping(triggers.get("pull_request"))
    if {"branches", "branches-ignore"} & set(pull_request):
        violations.append("causal gate may not use target-branch filters")
    event_types = pull_request.get("types")
    if not isinstance(event_types, list) or not CAUSAL_REQUIRED_TYPES.issubset(
        set(event_types)
    ):
        violations.append("causal gate is missing required pull-request activity types")

    environment = _mapping(workflow.get("env"))
    if environment.get("EXPECTED_SHA") != EXPECTED_SHA_EXPRESSION:
        violations.append("EXPECTED_SHA is not bound to the PR head")
    if environment.get("BASE_SHA") != "${{ github.event.pull_request.base.sha }}":
        violations.append("BASE_SHA is not bound to the PR base")
    if environment.get("BASE_REF") != "${{ github.event.pull_request.base.ref }}":
        violations.append("BASE_REF is not bound to the PR base branch")

    jobs = _mapping(workflow.get("jobs"))
    if _mapping(jobs.get("gate")).get("name") != "Causal PR Gate":
        violations.append("required check name changed")

    step_name_counts: Counter[str] = Counter()
    run_text: list[str] = []
    named_run_text: dict[str, str] = {}
    for raw_job in jobs.values():
        job = _mapping(raw_job)
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for raw_step in steps:
            step = _mapping(raw_step)
            name = step.get("name")
            if isinstance(name, str):
                step_name_counts[name] += 1
            run = step.get("run")
            if isinstance(run, str):
                run_text.append(run)
                if isinstance(name, str):
                    named_run_text.setdefault(name, run)

    for required_name in CRITICAL_STEP_NAMES:
        if step_name_counts[required_name] != 1:
            violations.append(
                f"critical step {required_name!r} must appear exactly once"
            )

    base_fetch = named_run_text.get("Fetch exact base commit", "")
    if "git fetch --no-tags" not in base_fetch:
        violations.append("exact base commit must be fetched explicitly")
    if _uses_shallow_fetch_option(base_fetch):
        violations.append("exact base fetch may not create a shallow ancestry boundary")

    joined_run_text = "\n".join(run_text)
    for required_directive in (
        '--require "final/base-freshness.json"',
        '--require "collected/base-freshness.json"',
    ):
        if required_directive not in joined_run_text:
            violations.append(
                f"final evidence manifest is missing {required_directive}"
            )

    return violations


def test_required_workflows_satisfy_trust_contract():
    report = verify_workflows(WORKFLOWS)
    assert report["passed"] is True, report["violations"]


def test_causal_workflow_satisfies_extended_contract():
    assert _causal_contract_violations(WORKFLOWS[-1]) == []


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
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[0],
        "persist-credentials: false",
        "persist-credentials: true",
    )
    assert any("credentials must not persist" in item for item in verify_workflow(mutated))


def test_contract_rejects_non_exact_checkout(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[0],
        "ref: ${{ env.EXPECTED_SHA }}",
        "ref: ${{ github.sha }}",
    )
    assert any("checkout ref is not exact-head bound" in item for item in verify_workflow(mutated))


def test_contract_rejects_missing_artifact_downgrade(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[0],
        "if-no-files-found: error",
        "if-no-files-found: warn",
    )
    assert any("missing evidence must be an error" in item for item in verify_workflow(mutated))


def test_contract_rejects_pull_request_target(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[0],
        "  pull_request:",
        "  pull_request_target:",
    )
    violations = verify_workflow(mutated)
    assert any("pull_request_target is forbidden" in item for item in violations)


def test_contract_rejects_duplicate_yaml_keys(tmp_path: Path):
    mutated = tmp_path / WORKFLOWS[0].name
    mutated.write_text(
        WORKFLOWS[0].read_text(encoding="utf-8") + "\npermissions: {}\n",
        encoding="utf-8",
    )
    assert any("duplicate key" in item for item in verify_workflow(mutated))


def test_causal_contract_rejects_target_branch_filter(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[-1],
        "  pull_request:\n    types:",
        "  pull_request:\n    branches: [main]\n    types:",
    )
    assert any(
        "target-branch filters" in item
        for item in _causal_contract_violations(mutated)
    )


def test_causal_contract_rejects_changed_check_name(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[-1],
        "name: Causal PR Gate",
        "name: Causal Gate",
    )
    assert any(
        "required check name changed" in item
        for item in _causal_contract_violations(mutated)
    )


def test_causal_contract_rejects_missing_edited_trigger(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[-1],
        "ready_for_review, edited",
        "ready_for_review",
    )
    assert any(
        "missing required pull-request activity types" in item
        for item in _causal_contract_violations(mutated)
    )


def test_causal_contract_rejects_unbound_expected_sha(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[-1],
        "EXPECTED_SHA: ${{ github.event.pull_request.head.sha || github.sha }}",
        "EXPECTED_SHA: ${{ github.sha }}",
    )
    assert any(
        "EXPECTED_SHA is not bound to the PR head" in item
        for item in _causal_contract_violations(mutated)
    )


def test_causal_contract_rejects_duplicate_critical_step_name(tmp_path: Path):
    original = (
        "      - name: Fetch exact base commit\n"
        "        run: |\n"
        "          test -n \"$BASE_SHA\""
    )
    duplicated = (
        "      - name: Fetch exact base commit\n"
        "        run: echo shadowed\n\n"
        + original
    )
    mutated = _mutate(tmp_path, WORKFLOWS[-1], original, duplicated)
    assert any(
        "must appear exactly once" in item
        for item in _causal_contract_violations(mutated)
    )


def test_causal_contract_rejects_every_shallow_base_fetch_option(
    tmp_path: Path,
):
    options = (
        "--depth=1",
        "--deepen=3",
        "--shallow-since=2024-01-01",
        "--shallow-exclude=HEAD",
    )
    for option in options:
        mutated = _mutate(
            tmp_path,
            WORKFLOWS[-1],
            "git fetch --no-tags \\",
            f"git fetch --no-tags {option} \\",
        )
        assert any(
            "shallow ancestry boundary" in item
            for item in _causal_contract_violations(mutated)
        ), option


def test_causal_contract_rejects_removed_base_recheck(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[-1],
        "Reconfirm base tip before final manifest",
        "Observe base tip before final manifest",
    )
    assert any(
        "must appear exactly once" in item
        for item in _causal_contract_violations(mutated)
    )


def test_causal_contract_rejects_detached_base_artifact(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        WORKFLOWS[-1],
        '--require "final/base-freshness.json"',
        '--require "final/other.json"',
    )
    assert any(
        "final/base-freshness.json" in item
        for item in _causal_contract_violations(mutated)
    )


def test_runbook_requires_up_to_date_branch_protection():
    runbook = (ROOT / "docs/ci/CAUSAL_PR_GATE.md").read_text(
        encoding="utf-8"
    )

    assert "Require branches to be up to date before merging" in runbook
    assert "`strict: true`" in runbook
    assert "base branch can still advance after a successful run" in runbook.casefold()
