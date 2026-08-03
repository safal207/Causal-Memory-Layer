from __future__ import annotations

import hashlib
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
TRUSTED_WORKFLOW = ROOT / ".github/workflows/trusted-pr-gate.yml"
CAUSAL_REQUIRED_TYPES = {
    "edited",
    "opened",
    "ready_for_review",
    "reopened",
    "synchronize",
}
TRUSTED_REQUIRED_TYPES = {
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
TRUSTED_CRITICAL_STEP_NAMES = (
    "Derive branch-scoped trust context",
    "Checkout protected base trust root",
    "Checkout untrusted subject as data only",
    "Verify exact head and protected file identities",
    "Bind target branch identity to trust evidence",
    "Publish branch-scoped trusted head status",
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _branch_scoped_context(base_ref: str) -> str:
    return "CML Trust Root Gate / " + hashlib.sha256(
        base_ref.encode("utf-8")
    ).hexdigest()


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


def _trusted_contract_violations(path: Path) -> list[str]:
    workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    assert isinstance(workflow, dict)
    violations: list[str] = []

    triggers = _mapping(workflow.get("on"))
    pull_request_target = _mapping(triggers.get("pull_request_target"))
    if not pull_request_target:
        violations.append("base trust-root gate must use pull_request_target")
    if {"branches", "branches-ignore"} & set(pull_request_target):
        violations.append("base trust-root gate may not use target-branch filters")
    event_types = pull_request_target.get("types")
    if not isinstance(event_types, list) or not TRUSTED_REQUIRED_TYPES.issubset(
        set(event_types)
    ):
        violations.append("base trust-root gate is missing required activity types")
    if workflow.get("permissions") != {}:
        violations.append("base trust-root workflow permissions must be empty")

    jobs = _mapping(workflow.get("jobs"))
    verify_job = _mapping(jobs.get("verify"))
    publish_job = _mapping(jobs.get("publish"))
    if verify_job.get("name") != "Verify protected CI contract":
        violations.append("base trust-root verification job identity changed")
    if publish_job.get("name") != "Publish trusted head status":
        violations.append("base trust-root publish job identity changed")
    if _mapping(verify_job.get("outputs")).get("status_context") != (
        "${{ steps.scope.outputs.status_context }}"
    ):
        violations.append("branch-scoped trust context is not exported by verify job")

    step_counts: Counter[str] = Counter()
    named_steps: dict[str, dict[str, Any]] = {}
    for raw_job in jobs.values():
        steps = _mapping(raw_job).get("steps")
        if not isinstance(steps, list):
            continue
        for raw_step in steps:
            step = _mapping(raw_step)
            name = step.get("name")
            if isinstance(name, str):
                step_counts[name] += 1
                named_steps.setdefault(name, step)

    for required_name in TRUSTED_CRITICAL_STEP_NAMES:
        if step_counts[required_name] != 1:
            violations.append(
                f"trusted critical step {required_name!r} must appear exactly once"
            )

    scope_step = named_steps.get("Derive branch-scoped trust context", {})
    scope_env = _mapping(scope_step.get("env"))
    scope_run = scope_step.get("run")
    if scope_step.get("id") != "scope":
        violations.append("branch-scoped trust context step id changed")
    if scope_env.get("BASE_REF") != "${{ github.event.pull_request.base.ref }}":
        violations.append("branch-scoped context is not bound to base ref")
    if scope_env.get("BASE_SHA") != "${{ github.event.pull_request.base.sha }}":
        violations.append("branch-scoped context is not bound to base SHA")
    if not isinstance(scope_run, str):
        scope_run = ""
    for fragment in (
        '"CML Trust Root Gate / " + hashlib.sha256(',
        'base_ref.encode("utf-8")',
        'output.write(f"status_context={context}\\n")',
    ):
        if fragment not in scope_run:
            violations.append(
                f"branch-scoped context derivation is missing {fragment}"
            )

    base_checkout = _mapping(
        named_steps.get("Checkout protected base trust root", {}).get("with")
    )
    if base_checkout.get("repository") != "${{ github.repository }}":
        violations.append("trusted base checkout repository is not base-owned")
    if base_checkout.get("ref") != "${{ github.event.pull_request.base.sha }}":
        violations.append("trusted base checkout is not bound to exact base SHA")
    if base_checkout.get("path") != "base":
        violations.append("trusted base checkout must use the isolated base path")
    if base_checkout.get("persist-credentials") != "false":
        violations.append("trusted base checkout credentials must not persist")

    subject_checkout = _mapping(
        named_steps.get("Checkout untrusted subject as data only", {}).get("with")
    )
    if subject_checkout.get("repository") != (
        "${{ github.event.pull_request.head.repo.full_name }}"
    ):
        violations.append("untrusted subject checkout is not bound to head repository")
    if subject_checkout.get("ref") != "${{ github.event.pull_request.head.sha }}":
        violations.append("untrusted subject checkout is not bound to exact head SHA")
    if subject_checkout.get("path") != "subject":
        violations.append("untrusted subject checkout must use the isolated subject path")
    if subject_checkout.get("persist-credentials") != "false":
        violations.append("untrusted subject checkout credentials must not persist")

    verify_run = named_steps.get(
        "Verify exact head and protected file identities", {}
    ).get("run")
    if not isinstance(verify_run, str):
        verify_run = ""
    for required_fragment in (
        "python base/.github/trust-root/scripts/verify_subject.py",
        "--base-root base",
        "--subject-root subject",
        '--expected-head "${{ github.event.pull_request.head.sha }}"',
    ):
        if required_fragment not in verify_run:
            violations.append(
                f"base trust-root verification is missing {required_fragment}"
            )

    evidence_step = named_steps.get(
        "Bind target branch identity to trust evidence", {}
    )
    evidence_env = _mapping(evidence_step.get("env"))
    evidence_run = evidence_step.get("run")
    if evidence_env.get("BASE_REF") != "${{ github.event.pull_request.base.ref }}":
        violations.append("trust evidence is not bound to exact base ref")
    if evidence_env.get("BASE_SHA") != "${{ github.event.pull_request.base.sha }}":
        violations.append("trust evidence is not bound to exact base SHA")
    if evidence_env.get("STATUS_CONTEXT") != (
        "${{ steps.scope.outputs.status_context }}"
    ):
        violations.append("trust evidence is not bound to branch-scoped context")
    if not isinstance(evidence_run, str):
        evidence_run = ""
    for fragment in (
        'payload["base_ref"] = base_ref',
        'payload["base_sha"] = base_sha',
        'payload["status_context"] = status_context',
    ):
        if fragment not in evidence_run:
            violations.append(f"trust evidence binding is missing {fragment}")

    publish_step = named_steps.get("Publish branch-scoped trusted head status", {})
    publish_env = _mapping(publish_step.get("env"))
    publish_run = publish_step.get("run")
    if publish_env.get("HEAD_SHA") != "${{ github.event.pull_request.head.sha }}":
        violations.append("trusted status is not bound to exact head SHA")
    if publish_env.get("BASE_REF") != "${{ github.event.pull_request.base.ref }}":
        violations.append("trusted status is not bound to exact base ref")
    if publish_env.get("BASE_SHA") != "${{ github.event.pull_request.base.sha }}":
        violations.append("trusted status is not bound to exact base SHA")
    if publish_env.get("STATUS_CONTEXT") != (
        "${{ needs.verify.outputs.status_context }}"
    ):
        violations.append("trusted status does not use exported branch context")
    if not isinstance(publish_run, str):
        publish_run = ""
    for fragment in (
        'expected_context = "CML Trust Root Gate / " + hashlib.sha256(',
        'base_ref.encode("utf-8")',
        '"context": status_context',
        'if status_context != expected_context:',
    ):
        if fragment not in publish_run:
            violations.append(
                f"trusted status is missing branch-scoped control {fragment}"
            )
    if '"context": "CML Trust Root Gate"' in publish_run:
        violations.append("trusted status uses a cross-branch constant context")

    return violations


def test_required_workflows_satisfy_trust_contract():
    report = verify_workflows(WORKFLOWS)
    assert report["passed"] is True, report["violations"]


def test_causal_workflow_satisfies_extended_contract():
    assert _causal_contract_violations(WORKFLOWS[-1]) == []


def test_base_trust_root_workflow_satisfies_extended_contract():
    assert _trusted_contract_violations(TRUSTED_WORKFLOW) == []


def test_same_head_against_two_base_refs_has_distinct_status_contexts():
    shared_head = "a" * 40
    main_context = _branch_scoped_context("main")
    maintenance_context = _branch_scoped_context("maintenance/1.x")

    assert shared_head == "a" * 40
    assert main_context != maintenance_context
    assert main_context == _branch_scoped_context("main")
    assert maintenance_context == _branch_scoped_context("maintenance/1.x")
    assert len(main_context) == len("CML Trust Root Gate / ") + 64


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


def test_trusted_contract_rejects_target_branch_filter(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        TRUSTED_WORKFLOW,
        "  pull_request_target:\n    types:",
        "  pull_request_target:\n    branches: [main]\n    types:",
    )
    assert any(
        "may not use target-branch filters" in item
        for item in _trusted_contract_violations(mutated)
    )


def test_trusted_contract_rejects_subject_executed_verifier(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        TRUSTED_WORKFLOW,
        "python base/.github/trust-root/scripts/verify_subject.py",
        "python subject/.github/trust-root/scripts/verify_subject.py",
    )
    assert any(
        "python base/.github/trust-root/scripts/verify_subject.py" in item
        for item in _trusted_contract_violations(mutated)
    )


def test_trusted_contract_rejects_unbound_subject_checkout(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        TRUSTED_WORKFLOW,
        "ref: ${{ github.event.pull_request.head.sha }}",
        "ref: ${{ github.sha }}",
    )
    assert any(
        "untrusted subject checkout is not bound to exact head SHA" in item
        for item in _trusted_contract_violations(mutated)
    )


def test_trusted_contract_rejects_constant_cross_branch_context(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        TRUSTED_WORKFLOW,
        '"context": status_context',
        '"context": "CML Trust Root Gate"',
    )
    assert any(
        "cross-branch constant context" in item
        for item in _trusted_contract_violations(mutated)
    )


def test_trusted_contract_rejects_evidence_without_exact_base_sha(tmp_path: Path):
    mutated = _mutate(
        tmp_path,
        TRUSTED_WORKFLOW,
        'payload["base_sha"] = base_sha',
        'payload["observed_sha"] = base_sha',
    )
    assert any(
        'payload["base_sha"] = base_sha' in item
        for item in _trusted_contract_violations(mutated)
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
    assert "`CML Trust Root Gate`" in runbook
    assert "every protected target branch" in runbook
