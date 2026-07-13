#!/usr/bin/env python3
"""Validate the non-negotiable trust properties of required CML workflows."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Iterable

import yaml

from scripts.ci.assert_exact_head import write_json_atomic

PINNED_ACTION = re.compile(r"^[^/@\s]+/[^/@\s]+(?:/[^/@\s]+)*@[0-9a-f]{40}$")
EXPECTED_SHA_EXPRESSION = "${{ github.event.pull_request.head.sha || github.sha }}"
SOURCE_REPOSITORY_EXPRESSION = (
    "${{ github.event.pull_request.head.repo.full_name || github.repository }}"
)
REQUIRED_JOB_NAMES = {
    "ci.yml": {"gate": "CML CI Gate"},
    "python-package-validation.yml": {
        "package-validation": "Build, check, install, and smoke-test package"
    },
    "security.yml": {"security-gate": "Security Gate"},
}


class UniqueKeyLoader(yaml.BaseLoader):
    """Load scalar values as text while rejecting ambiguous duplicate keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_workflow(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"workflow must be a mapping: {path}")
    return loaded


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    value = job.get("steps")
    if not isinstance(value, list):
        return []
    return [step for step in value if isinstance(step, dict)]


def verify_workflow(path: Path) -> list[str]:
    violations: list[str] = []
    try:
        workflow = _load_workflow(path)
    except ValueError as exc:
        return [str(exc)]

    label = path.name
    triggers = _mapping(workflow.get("on"))
    if "pull_request_target" in triggers:
        violations.append(f"{label}: pull_request_target is forbidden for untrusted code")
    if "pull_request" not in triggers:
        violations.append(f"{label}: required workflows must run for every pull request")
    else:
        pull_request = triggers.get("pull_request")
        if isinstance(pull_request, dict) and ({"paths", "paths-ignore"} & set(pull_request)):
            violations.append(f"{label}: required pull-request checks may not use path filters")

    if workflow.get("permissions") != {}:
        violations.append(f"{label}: workflow-level permissions must be empty")

    concurrency = _mapping(workflow.get("concurrency"))
    if not concurrency.get("group") or concurrency.get("cancel-in-progress") != "true":
        violations.append(f"{label}: concurrency must cancel superseded runs")

    environment = _mapping(workflow.get("env"))
    if environment.get("EXPECTED_SHA") != EXPECTED_SHA_EXPRESSION:
        violations.append(f"{label}: EXPECTED_SHA is not bound to the PR head")
    if environment.get("SOURCE_REPOSITORY") != SOURCE_REPOSITORY_EXPRESSION:
        violations.append(f"{label}: SOURCE_REPOSITORY is not bound to the PR head repository")

    jobs = _mapping(workflow.get("jobs"))
    if not jobs:
        violations.append(f"{label}: workflow has no jobs")
        return violations

    checkout_count = 0
    upload_count = 0
    for job_id, raw_job in jobs.items():
        if not isinstance(raw_job, dict):
            violations.append(f"{label}:{job_id}: job must be a mapping")
            continue
        job = raw_job
        if "timeout-minutes" not in job:
            violations.append(f"{label}:{job_id}: timeout-minutes is required")
        if not isinstance(job.get("permissions"), dict):
            violations.append(f"{label}:{job_id}: explicit job permissions are required")
        for scope, access in _mapping(job.get("permissions")).items():
            if access == "write" and not (
                label == "security.yml" and job_id == "codeql" and scope == "security-events"
            ):
                violations.append(f"{label}:{job_id}: unexpected write permission for {scope}")
        if job.get("continue-on-error") == "true":
            violations.append(f"{label}:{job_id}: continue-on-error is forbidden")

        job_steps = _steps(job)
        job_checkout_count = 0
        for index, step in enumerate(job_steps):
            step_label = f"{label}:{job_id}:step-{index + 1}"
            if step.get("continue-on-error") == "true":
                violations.append(f"{step_label}: continue-on-error is forbidden")
            action = step.get("uses")
            if not isinstance(action, str):
                continue
            if action.startswith("./"):
                continue
            if not PINNED_ACTION.fullmatch(action):
                violations.append(f"{step_label}: external action is not pinned to a full SHA")

            action_name = action.split("@", 1)[0]
            inputs = _mapping(step.get("with"))
            if action_name == "actions/checkout":
                checkout_count += 1
                job_checkout_count += 1
                if inputs.get("ref") != "${{ env.EXPECTED_SHA }}":
                    violations.append(f"{step_label}: checkout ref is not exact-head bound")
                if inputs.get("repository") != "${{ env.SOURCE_REPOSITORY }}":
                    violations.append(f"{step_label}: checkout repository is not head-repo bound")
                if inputs.get("persist-credentials") != "false":
                    violations.append(f"{step_label}: checkout credentials must not persist")
            if action_name == "actions/upload-artifact":
                upload_count += 1
                if inputs.get("if-no-files-found") != "error":
                    violations.append(f"{step_label}: missing evidence must be an error")

        if job_checkout_count == 0:
            violations.append(f"{label}:{job_id}: every required job must verify an exact checkout")

    if checkout_count == 0:
        violations.append(f"{label}: workflow has no exact-head checkout")
    if upload_count == 0:
        violations.append(f"{label}: workflow has no fail-closed evidence upload")

    for job_id, required_name in REQUIRED_JOB_NAMES.get(label, {}).items():
        actual_name = _mapping(jobs.get(job_id)).get("name")
        if actual_name != required_name:
            violations.append(
                f"{label}:{job_id}: required check name changed from {required_name!r}"
            )
    return violations


def verify_workflows(paths: Iterable[Path]) -> dict[str, Any]:
    files = [Path(path) for path in paths]
    violations = [violation for path in files for violation in verify_workflow(path)]
    return {
        "schema_version": "cml-ci-workflow-contract-v1",
        "passed": not violations,
        "files": [path.as_posix() for path in files],
        "violations": violations,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflows", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = verify_workflows(args.workflows)
    write_json_atomic(args.output, report)
    if report["violations"]:
        for violation in report["violations"]:
            print(f"CI contract violation: {violation}")
        raise SystemExit(1)
    print(f"CI workflow contract verified for {len(report['files'])} workflows")


if __name__ == "__main__":
    main()
