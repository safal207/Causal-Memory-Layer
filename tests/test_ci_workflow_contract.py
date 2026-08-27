from __future__ import annotations

import hashlib
import json
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
CAUSAL_WORKFLOW = ROOT / ".github/workflows/causal-pr.yml"
WORKFLOWS = [
    ROOT / ".github/workflows/ci.yml",
    ROOT / ".github/workflows/python-package-validation.yml",
    ROOT / ".github/workflows/security.yml",
    CAUSAL_WORKFLOW,
    ROOT / ".github/workflows/ebpf-runtime-proof.yml",
]
TRUSTED_WORKFLOW = ROOT / ".github/workflows/trusted-pr-gate.yml"
REFRESH_WORKFLOW = ROOT / ".github/workflows/trust-root-refresh.yml"
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
CAUSAL_CRITICAL_STEPS = (
    "Fetch exact base commit",
    "Reconfirm base tip before evidence",
    "Reconfirm base tip before final manifest",
)
TRUSTED_CRITICAL_STEPS = (
    "Derive branch-scoped trust context",
    "Resolve exact test merge identity",
    "Checkout protected base trust root",
    "Checkout untrusted subject as data only",
    "Verify exact head and protected file identities",
    "Bind exact transition identity to trust evidence",
    "Publish branch-scoped test merge status",
)
REFRESH_CRITICAL_STEPS = (
    "Checkout trusted refresh orchestrator",
    "Enumerate exact open pull request identities",
    "Derive refresh trust context",
    "Mark current test merge verification pending",
    "Checkout exact target base trust root",
    "Checkout exact untrusted subject as data only",
    "Run exact-base trust verification",
    "Reconfirm current pull request transition",
    "Publish refreshed test merge status",
    "Require refreshed verification and current transition",
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _load(path: Path) -> dict[str, Any]:
    workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    assert isinstance(workflow, dict)
    return workflow


def _steps_by_name(jobs: dict[str, Any]) -> tuple[Counter[str], dict[str, dict[str, Any]]]:
    counts: Counter[str] = Counter()
    named: dict[str, dict[str, Any]] = {}
    for raw_job in jobs.values():
        steps = _mapping(raw_job).get("steps")
        if not isinstance(steps, list):
            continue
        for raw_step in steps:
            step = _mapping(raw_step)
            name = step.get("name")
            if isinstance(name, str):
                counts[name] += 1
                named.setdefault(name, step)
    return counts, named


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


def _require_fragments(
    violations: list[str], script: Any, label: str, fragments: tuple[str, ...]
) -> str:
    text = script if isinstance(script, str) else ""
    for fragment in fragments:
        if fragment not in text:
            violations.append(f"{label} is missing {fragment}")
    return text


def _causal_contract_violations(path: Path) -> list[str]:
    workflow = _load(path)
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
    counts, named = _steps_by_name(jobs)
    for name in CAUSAL_CRITICAL_STEPS:
        if counts[name] != 1:
            violations.append(f"critical step {name!r} must appear exactly once")

    base_fetch = named.get("Fetch exact base commit", {}).get("run")
    base_fetch = base_fetch if isinstance(base_fetch, str) else ""
    if "git fetch --no-tags" not in base_fetch:
        violations.append("exact base commit must be fetched explicitly")
    if _uses_shallow_fetch_option(base_fetch):
        violations.append("exact base fetch may not create a shallow ancestry boundary")

    run_text = "\n".join(
        step.get("run", "")
        for step in named.values()
        if isinstance(step.get("run"), str)
    )
    for directive in (
        '--require "final/base-freshness.json"',
        '--require "collected/base-freshness.json"',
    ):
        if directive not in run_text:
            violations.append(f"final evidence manifest is missing {directive}")
    return violations


def _trusted_contract_violations(path: Path) -> list[str]:
    workflow = _load(path)
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
    if publish_job.get("name") != "Publish trusted merge status":
        violations.append("base trust-root publish job identity changed")
    outputs = _mapping(verify_job.get("outputs"))
    if outputs.get("status_context") != "${{ steps.scope.outputs.status_context }}":
        violations.append("branch-scoped trust context is not exported")
    if outputs.get("merge_sha") != "${{ steps.identity.outputs.merge_sha }}":
        violations.append("test merge SHA is not exported")

    counts, named = _steps_by_name(jobs)
    for name in TRUSTED_CRITICAL_STEPS:
        if counts[name] != 1:
            violations.append(f"trusted critical step {name!r} must appear exactly once")

    scope = named.get("Derive branch-scoped trust context", {})
    if scope.get("id") != "scope":
        violations.append("branch-scoped trust context step id changed")
    scope_env = _mapping(scope.get("env"))
    if scope_env.get("BASE_REF") != "${{ github.event.pull_request.base.ref }}":
        violations.append("branch-scoped context is not bound to base ref")
    _require_fragments(
        violations,
        scope.get("run"),
        "branch-scoped context",
        (
            '"CML Trust Root Gate / " + hashlib.sha256(',
            'base_ref.encode("utf-8")',
            'output.write(f"status_context={context}\\n")',
        ),
    )

    identity = named.get("Resolve exact test merge identity", {})
    if identity.get("id") != "identity":
        violations.append("test merge identity step id changed")
    identity_env = _mapping(identity.get("env"))
    expected_identity_env = {
        "EXPECTED_BASE_REF": "${{ github.event.pull_request.base.ref }}",
        "EXPECTED_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "EXPECTED_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
        "EXPECTED_HEAD_REPOSITORY": "${{ github.event.pull_request.head.repo.full_name }}",
    }
    for key, value in expected_identity_env.items():
        if identity_env.get(key) != value:
            violations.append(f"test merge identity is not bound to {key}")
    _require_fragments(
        violations,
        identity.get("run"),
        "test merge identity",
        (
            'payload.get("merge_commit_sha")',
            '"merge_sha": str(payload.get("merge_commit_sha", "")).lower()',
            'output.write(f"merge_sha={observed[\'merge_sha\']}\\n")',
        ),
    )

    base_checkout = _mapping(
        named.get("Checkout protected base trust root", {}).get("with")
    )
    if base_checkout.get("repository") != "${{ github.repository }}":
        violations.append("trusted base checkout repository is not base-owned")
    if base_checkout.get("ref") != "${{ github.event.pull_request.base.sha }}":
        violations.append("trusted base checkout is not bound to exact base SHA")
    if base_checkout.get("path") != "base":
        violations.append("trusted base checkout must use isolated base path")
    if base_checkout.get("persist-credentials") != "false":
        violations.append("trusted base checkout credentials must not persist")

    subject_checkout = _mapping(
        named.get("Checkout untrusted subject as data only", {}).get("with")
    )
    if subject_checkout.get("repository") != (
        "${{ github.event.pull_request.head.repo.full_name }}"
    ):
        violations.append("subject checkout is not bound to head repository")
    if subject_checkout.get("ref") != "${{ github.event.pull_request.head.sha }}":
        violations.append("subject checkout is not bound to exact head SHA")
    if subject_checkout.get("path") != "subject":
        violations.append("subject checkout must use isolated subject path")
    if subject_checkout.get("persist-credentials") != "false":
        violations.append("subject checkout credentials must not persist")

    verify_run = named.get(
        "Verify exact head and protected file identities", {}
    ).get("run")
    _require_fragments(
        violations,
        verify_run,
        "base trust-root verification",
        (
            "python base/.github/trust-root/scripts/verify_subject.py",
            "--base-root base",
            "--subject-root subject",
            '--expected-head "${{ github.event.pull_request.head.sha }}"',
        ),
    )

    evidence = named.get("Bind exact transition identity to trust evidence", {})
    evidence_env = _mapping(evidence.get("env"))
    expected_evidence_env = {
        "BASE_REF": "${{ github.event.pull_request.base.ref }}",
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
        "MERGE_SHA": "${{ steps.identity.outputs.merge_sha }}",
        "STATUS_CONTEXT": "${{ steps.scope.outputs.status_context }}",
    }
    for key, value in expected_evidence_env.items():
        if evidence_env.get(key) != value:
            violations.append(f"trust evidence is not bound to {key}")
    _require_fragments(
        violations,
        evidence.get("run"),
        "trust evidence binding",
        ('"merge_sha": os.environ["MERGE_SHA"]', "payload.update(values)"),
    )

    publish = named.get("Publish branch-scoped test merge status", {})
    publish_env = _mapping(publish.get("env"))
    expected_publish_env = {
        "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
        "BASE_REF": "${{ github.event.pull_request.base.ref }}",
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "MERGE_SHA": "${{ needs.verify.outputs.merge_sha }}",
        "STATUS_CONTEXT": "${{ needs.verify.outputs.status_context }}",
    }
    for key, value in expected_publish_env.items():
        if publish_env.get(key) != value:
            violations.append(f"trusted merge status is not bound to {key}")
    publish_run = _require_fragments(
        violations,
        publish.get("run"),
        "trusted merge status",
        (
            'expected_context = "CML Trust Root Gate / " + hashlib.sha256(',
            "current_identity",
            "expected_identity",
            'f"https://api.github.com/repos/{repository}/statuses/{merge_sha}"',
            '"context": status_context',
        ),
    )
    if 'statuses/{head_sha}' in publish_run:
        violations.append("trusted status is published to head instead of test merge")
    if '"context": "CML Trust Root Gate"' in publish_run:
        violations.append("trusted status uses a cross-branch constant context")
    return violations


def _refresh_contract_violations(path: Path) -> list[str]:
    workflow = _load(path)
    violations: list[str] = []
    triggers = _mapping(workflow.get("on"))
    if "push" in triggers:
        violations.append("refresh workflow may not run untrusted branch code on push")
    if "workflow_dispatch" in triggers:
        violations.append(
            "refresh workflow may not expose manual dispatch from selectable refs"
        )
    schedule = triggers.get("schedule")
    if not isinstance(schedule, list) or not any(
        _mapping(item).get("cron") == "*/5 * * * *" for item in schedule
    ):
        violations.append("refresh workflow must run every five minutes")
    if workflow.get("permissions") != {}:
        violations.append("refresh workflow permissions must be empty")

    jobs = _mapping(workflow.get("jobs"))
    enumerate_job = _mapping(jobs.get("enumerate"))
    refresh_job = _mapping(jobs.get("refresh"))
    if enumerate_job.get("name") != "Enumerate current pull request transitions":
        violations.append("refresh enumeration job identity changed")
    if _mapping(enumerate_job.get("outputs")).get("matrix") != (
        "${{ steps.targets.outputs.matrix }}"
    ):
        violations.append("refresh matrix is not exported")
    refresh_permissions = _mapping(refresh_job.get("permissions"))
    for scope, access in {
        "contents": "read",
        "pull-requests": "read",
        "statuses": "write",
    }.items():
        if refresh_permissions.get(scope) != access:
            violations.append(f"refresh job permission changed: {scope}")
    strategy = _mapping(refresh_job.get("strategy"))
    if strategy.get("fail-fast") != "false":
        violations.append("refresh matrix must not fail fast")
    if strategy.get("matrix") != "${{ fromJSON(needs.enumerate.outputs.matrix) }}":
        violations.append("refresh job is not bound to enumerated matrix")

    counts, named = _steps_by_name(jobs)
    for name in REFRESH_CRITICAL_STEPS:
        if counts[name] != 1:
            violations.append(f"refresh critical step {name!r} must appear exactly once")

    orchestrator = _mapping(
        named.get("Checkout trusted refresh orchestrator", {}).get("with")
    )
    if orchestrator.get("ref") != "${{ github.sha }}":
        violations.append("refresh orchestrator is not bound to default-branch SHA")
    if orchestrator.get("persist-credentials") != "false":
        violations.append("refresh orchestrator credentials must not persist")

    enumerate_step = named.get("Enumerate exact open pull request identities", {})
    if enumerate_step.get("id") != "targets":
        violations.append("refresh target enumeration id changed")
    _require_fragments(
        violations,
        enumerate_step.get("run"),
        "refresh enumeration",
        (
            '"state": "open"',
            '"base_sha"',
            '"head_sha"',
            '"merge_sha"',
            'if not re.fullmatch(r"[0-9a-f]{40}", target["merge_sha"]):',
            '"reason": "test_merge_unavailable"',
            '"skipped": skipped',
            "continue\n        targets.append(target)",
            'output.write("matrix="',
        ),
    )

    pending = named.get("Mark current test merge verification pending", {})
    pending_env = _mapping(pending.get("env"))
    if pending_env.get("STATUS_CONTEXT") != "${{ steps.scope.outputs.status_context }}":
        violations.append("pending status is not bound to refresh context")
    pending_run = _require_fragments(
        violations,
        pending.get("run"),
        "pending test merge status",
        ('"state": "pending"', "statuses/{os.environ['MERGE_SHA']}"),
    )
    if "statuses/{os.environ['HEAD_SHA']}" in pending_run:
        violations.append("pending refresh status targets head instead of merge")

    base_checkout = _mapping(
        named.get("Checkout exact target base trust root", {}).get("with")
    )
    if base_checkout.get("ref") != "${{ matrix.base_sha }}":
        violations.append("refresh base checkout is not exact")
    subject_checkout = _mapping(
        named.get("Checkout exact untrusted subject as data only", {}).get("with")
    )
    if subject_checkout.get("repository") != "${{ matrix.head_repository }}":
        violations.append("refresh subject repository is not exact")
    if subject_checkout.get("ref") != "${{ matrix.head_sha }}":
        violations.append("refresh subject SHA is not exact")

    _require_fragments(
        violations,
        named.get("Run exact-base trust verification", {}).get("run"),
        "refresh trust verification",
        (
            '"base/.github/trust-root/scripts/verify_subject.py"',
            '"merge_sha": os.environ["MERGE_SHA"]',
            'output.write("result="',
        ),
    )
    freshness = named.get("Reconfirm current pull request transition", {})
    if freshness.get("id") != "freshness":
        violations.append("refresh freshness step id changed")
    _require_fragments(
        violations,
        freshness.get("run"),
        "refresh transition freshness",
        ("observed == expected", 'output.write("fresh="'),
    )
    final_publish = named.get("Publish refreshed test merge status", {})
    final_run = _require_fragments(
        violations,
        final_publish.get("run"),
        "refreshed test merge status",
        (
            'if os.environ["TRANSITION_FRESH"] != "true":',
            "statuses/{os.environ['MERGE_SHA']}",
            '"context": os.environ["STATUS_CONTEXT"]',
        ),
    )
    if "statuses/{os.environ['HEAD_SHA']}" in final_run:
        violations.append("final refresh status targets head instead of merge")
    _require_fragments(
        violations,
        named.get("Require refreshed verification and current transition", {}).get(
            "run"
        ),
        "refresh final requirement",
        ('test "$VERIFY_RESULT" = "success"', 'test "$TRANSITION_FRESH" = "true"'),
    )
    return violations


def test_required_workflows_satisfy_trust_contract():
    report = verify_workflows(WORKFLOWS)
    assert report["passed"] is True, report["violations"]


def test_extended_trust_contracts_pass():
    assert _causal_contract_violations(CAUSAL_WORKFLOW) == []
    assert _trusted_contract_violations(TRUSTED_WORKFLOW) == []
    assert _refresh_contract_violations(REFRESH_WORKFLOW) == []


def test_status_identity_changes_when_base_transition_changes():
    context = _branch_scoped_context("main")
    shared_head = "a" * 40
    old_merge = "b" * 40
    new_merge = "c" * 40
    assert (context, shared_head, old_merge) != (context, shared_head, new_merge)


def test_same_head_against_two_base_refs_has_distinct_status_contexts():
    assert _branch_scoped_context("main") != _branch_scoped_context(
        "maintenance/1.x"
    )


def test_ebpf_runtime_evidence_entrypoints_are_trust_root_pinned():
    manifest = json.loads(
        (ROOT / ".github/trust-root/protected_files.json").read_text(encoding="utf-8")
    )
    protected = set(manifest["files"])
    required = {
        ".github/workflows/ebpf-runtime-proof.yml",
        "cml/integrations/ebpf_fd_reuse_runtime.py",
        "vcml/linux-ebpf/runtime_fd_reuse_proof.py",
        "vcml/linux-ebpf/runtime_read_binding_trust_entrypoint.py",
    }
    assert required <= protected


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


def test_standard_contract_mutations_fail(tmp_path: Path):
    mutations = (
        (
            "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
            "actions/checkout@v6",
            "not pinned to a full SHA",
        ),
        ("persist-credentials: false", "persist-credentials: true", "credentials"),
        ("ref: ${{ env.EXPECTED_SHA }}", "ref: ${{ github.sha }}", "checkout ref"),
        ("if-no-files-found: error", "if-no-files-found: warn", "missing evidence"),
        ("  pull_request:", "  pull_request_target:", "pull_request_target"),
    )
    for old, new, expected in mutations:
        mutated = _mutate(tmp_path, WORKFLOWS[0], old, new)
        assert any(expected in item for item in verify_workflow(mutated))


def test_contract_rejects_duplicate_yaml_keys(tmp_path: Path):
    mutated = tmp_path / WORKFLOWS[0].name
    mutated.write_text(
        WORKFLOWS[0].read_text(encoding="utf-8") + "\npermissions: {}\n",
        encoding="utf-8",
    )
    assert any("duplicate key" in item for item in verify_workflow(mutated))


def test_causal_contract_mutations_fail(tmp_path: Path):
    cases = (
        (
            "  pull_request:\n    types:",
            "  pull_request:\n    branches: [main]\n    types:",
            "target-branch filters",
        ),
        ("name: Causal PR Gate", "name: Causal Gate", "required check name"),
        ("ready_for_review, edited", "ready_for_review", "missing required"),
        (
            "EXPECTED_SHA: ${{ github.event.pull_request.head.sha || github.sha }}",
            "EXPECTED_SHA: ${{ github.sha }}",
            "EXPECTED_SHA",
        ),
        (
            "Reconfirm base tip before final manifest",
            "Observe base tip before final manifest",
            "exactly once",
        ),
        (
            '--require "final/base-freshness.json"',
            '--require "final/other.json"',
            "final/base-freshness.json",
        ),
    )
    for old, new, expected in cases:
        mutated = _mutate(tmp_path, CAUSAL_WORKFLOW, old, new)
        assert any(expected in item for item in _causal_contract_violations(mutated))


def test_causal_contract_rejects_duplicate_and_shallow_steps(tmp_path: Path):
    original = (
        "      - name: Fetch exact base commit\n"
        "        run: |\n"
        "          test -n \"$BASE_SHA\""
    )
    duplicated = "      - name: Fetch exact base commit\n        run: echo shadowed\n\n" + original
    mutated = _mutate(tmp_path, CAUSAL_WORKFLOW, original, duplicated)
    assert any("exactly once" in item for item in _causal_contract_violations(mutated))

    for option in (
        "--depth=1",
        "--deepen=3",
        "--shallow-since=2024-01-01",
        "--shallow-exclude=HEAD",
    ):
        mutated = _mutate(
            tmp_path,
            CAUSAL_WORKFLOW,
            "git fetch --no-tags \\",
            f"git fetch --no-tags {option} \\",
        )
        assert any(
            "shallow ancestry boundary" in item
            for item in _causal_contract_violations(mutated)
        )


def test_trusted_contract_mutations_fail(tmp_path: Path):
    cases = (
        (
            "  pull_request_target:\n    types:",
            "  pull_request_target:\n    branches: [main]\n    types:",
            "target-branch filters",
        ),
        (
            "python base/.github/trust-root/scripts/verify_subject.py",
            "python subject/.github/trust-root/scripts/verify_subject.py",
            "base/.github/trust-root/scripts/verify_subject.py",
        ),
        (
            "ref: ${{ github.event.pull_request.head.sha }}",
            "ref: ${{ github.sha }}",
            "subject checkout is not bound",
        ),
        (
            '"context": status_context',
            '"context": "CML Trust Root Gate"',
            "cross-branch constant context",
        ),
        (
            'statuses/{merge_sha}',
            'statuses/{head_sha}',
            "head instead of test merge",
        ),
        (
            "merge_sha: ${{ steps.identity.outputs.merge_sha }}",
            "merge_sha: ${{ github.event.pull_request.head.sha }}",
            "test merge SHA is not exported",
        ),
    )
    for old, new, expected in cases:
        mutated = _mutate(tmp_path, TRUSTED_WORKFLOW, old, new)
        assert any(expected in item for item in _trusted_contract_violations(mutated))


def test_refresh_contract_mutations_fail(tmp_path: Path):
    cases = (
        ('cron: "*/5 * * * *"', 'cron: "0 * * * *"', "every five minutes"),
        (
            "  schedule:\n",
            "  push:\n  schedule:\n",
            "may not run untrusted branch code on push",
        ),
        (
            "  schedule:\n",
            "  workflow_dispatch:\n  schedule:\n",
            "manual dispatch from selectable refs",
        ),
        (
            "base/.github/trust-root/scripts/verify_subject.py",
            "subject/.github/trust-root/scripts/verify_subject.py",
            "base/.github/trust-root/scripts/verify_subject.py",
        ),
        (
            "statuses/{os.environ['MERGE_SHA']}",
            "statuses/{os.environ['HEAD_SHA']}",
            "head instead of merge",
        ),
        (
            "observed == expected",
            "True",
            "observed == expected",
        ),
    )
    for old, new, expected in cases:
        mutated = _mutate(tmp_path, REFRESH_WORKFLOW, old, new)
        assert any(expected in item for item in _refresh_contract_violations(mutated))


def test_refresh_contract_requires_unavailable_test_merges_to_be_isolated(
    tmp_path: Path,
):
    mutated = _mutate(
        tmp_path,
        REFRESH_WORKFLOW,
        '"reason": "test_merge_unavailable"',
        '"reason": "ignored"',
    )
    assert any(
        "test_merge_unavailable" in item
        for item in _refresh_contract_violations(mutated)
    )

    mutated = _mutate(
        tmp_path,
        REFRESH_WORKFLOW,
        "continue\n                  targets.append(target)",
        'raise SystemExit("merge unavailable")\n                  targets.append(target)',
    )
    assert any(
        "targets.append" in item
        for item in _refresh_contract_violations(mutated)
    )


def test_runbook_requires_current_test_merge_protection():
    runbook = (ROOT / "docs/ci/CAUSAL_PR_GATE.md").read_text(encoding="utf-8")
    assert "test merge commit" in runbook.casefold()
    assert "CML Trust Root Refresh" in runbook
    assert "Require branches to be up to date before merging" in runbook
    assert "`strict: true`" in runbook
