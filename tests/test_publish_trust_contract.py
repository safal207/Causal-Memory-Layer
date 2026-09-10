from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from scripts.ci.verify_workflow_contract import PINNED_ACTION, UniqueKeyLoader

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_REL = ".github/workflows/publish-python-package.yml"
PUBLISH_WORKFLOW = ROOT / PUBLISH_REL
LEGACY_PUBLISH_WORKFLOW = ROOT / ".github/workflows/publish-pypi.yml"
REFRESH_WORKFLOW = ROOT / ".github/workflows/trust-root-refresh.yml"
PROTECTED_MANIFEST = ROOT / ".github/trust-root/protected_files.json"
THIS_TEST_REL = "tests/test_publish_trust_contract.py"
PYPI_PUBLISH_ACTION = "pypa/gh-action-pypi-publish"
MAIN_REF_GUARD = "github.ref == 'refs/heads/main'"


def _load(path: Path) -> dict[str, Any]:
    payload = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    assert isinstance(payload, dict)
    return payload


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    raw = job.get("steps")
    return [step for step in raw if isinstance(step, dict)] if isinstance(raw, list) else []


def _git_blob_id(path: Path) -> str:
    data = path.read_bytes()
    payload = f"blob {len(data)}\0".encode("ascii") + data
    return hashlib.sha1(payload).hexdigest()


def _named_step(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    for raw_job in _mapping(workflow.get("jobs")).values():
        for step in _steps(_mapping(raw_job)):
            if step.get("name") == name:
                return step
    raise AssertionError(f"missing workflow step: {name}")


def _verification_program() -> str:
    workflow = _load(REFRESH_WORKFLOW)
    script = _named_step(workflow, "Run exact-base trust verification").get("run")
    assert isinstance(script, str)
    prefix = "python3 - <<'PY'\n"
    suffix = "\nPY"
    assert script.startswith(prefix)
    assert script.endswith(suffix)
    return script[len(prefix) : -len(suffix)]


def test_release_authority_has_one_canonical_workflow():
    assert PUBLISH_WORKFLOW.is_file()
    assert not LEGACY_PUBLISH_WORKFLOW.exists()


def test_canonical_publish_workflow_pins_every_external_action():
    workflow = _load(PUBLISH_WORKFLOW)
    actions: list[str] = []
    for raw_job in _mapping(workflow.get("jobs")).values():
        for step in _steps(_mapping(raw_job)):
            action = step.get("uses")
            if isinstance(action, str) and not action.startswith("./"):
                actions.append(action)
                assert PINNED_ACTION.fullmatch(action), action
    assert actions
    assert sum(action.startswith(PYPI_PUBLISH_ACTION + "@") for action in actions) == 2


def test_build_checkout_is_exact_and_non_persistent():
    workflow = _load(PUBLISH_WORKFLOW)
    checkout = _named_step(workflow, "Checkout repository")
    inputs = _mapping(checkout.get("with"))
    assert inputs.get("repository") == "${{ github.repository }}"
    assert inputs.get("ref") == "${{ github.sha }}"
    assert inputs.get("persist-credentials") == "false"

    upload = _named_step(workflow, "Upload distributions artifact")
    assert _mapping(upload.get("with")).get("if-no-files-found") == "error"


def test_oidc_is_scoped_only_to_publish_jobs():
    workflow = _load(PUBLISH_WORKFLOW)
    assert workflow.get("permissions") == {}
    jobs = _mapping(workflow.get("jobs"))
    assert _mapping(_mapping(jobs.get("build")).get("permissions")) == {
        "contents": "read"
    }
    expected_publish_permissions = {"contents": "read", "id-token": "write"}
    for job_id in ("publish-testpypi", "publish-pypi"):
        assert _mapping(_mapping(jobs.get(job_id)).get("permissions")) == (
            expected_publish_permissions
        )


def test_manual_publish_is_main_only_and_release_tag_matches_version():
    workflow = _load(PUBLISH_WORKFLOW)
    jobs = _mapping(workflow.get("jobs"))
    for job_id in ("publish-testpypi", "publish-pypi"):
        condition = _mapping(jobs.get(job_id)).get("if")
        assert isinstance(condition, str)
        assert MAIN_REF_GUARD in condition

    version_guard = _named_step(workflow, "Verify release tag matches package version")
    assert version_guard.get("if") == "github.event_name == 'release'"
    script = version_guard.get("run")
    assert isinstance(script, str)
    for fragment in (
        'tag="${GITHUB_REF_NAME#v}"',
        'tomllib.load(open("pyproject.toml", "rb"))["project"]["version"]',
        'if [ "$tag" != "$package_version" ]; then',
    ):
        assert fragment in script


def test_publish_workflow_and_contract_are_exact_trust_root_entries():
    manifest = json.loads(PROTECTED_MANIFEST.read_text(encoding="utf-8"))
    protected = manifest["files"]
    assert protected[PUBLISH_REL] == _git_blob_id(PUBLISH_WORKFLOW)
    assert protected[THIS_TEST_REL] == _git_blob_id(ROOT / THIS_TEST_REL)


def test_refresh_success_status_requires_verified_current_transition():
    workflow = _load(REFRESH_WORKFLOW)
    script = _named_step(workflow, "Publish refreshed test merge status").get("run")
    assert isinstance(script, str)
    required = (
        'if os.environ["TRANSITION_FRESH"] != "true":',
        'passed = os.environ["VERIFY_RESULT"] == "success"',
        '"state": "success" if passed else "failure"',
        "statuses/{os.environ['MERGE_SHA']}",
    )
    for fragment in required:
        assert fragment in script


def test_refresh_verifier_distinguishes_denial_from_execution_error():
    script = _named_step(_load(REFRESH_WORKFLOW), "Run exact-base trust verification").get(
        "run"
    )
    assert isinstance(script, str)
    required = (
        'passed = completed.returncode == 0 and payload.get("passed") is True',
        'findings = payload.get("findings")',
        'completed.returncode != 0',
        'and payload.get("passed") is False',
        'and isinstance(findings, list)',
        'and bool(findings)',
        'and payload.get("error") is None',
        'outcome = "denied"',
        'outcome = "error"',
        '"refresh_outcome": outcome',
        'output.write("outcome=" + outcome + "\\n")',
        'if outcome == "error":',
        'raise SystemExit("trust verifier execution or evidence failed")',
    )
    for fragment in required:
        assert fragment in script


def test_refresh_verifier_outcome_matrix_executes_actual_workflow_program(
    tmp_path: Path,
):
    verifier = tmp_path / "base/.github/trust-root/scripts/verify_subject.py"
    verifier.parent.mkdir(parents=True)
    verifier.write_text(
        """from pathlib import Path
import json
import os
import sys

mode = os.environ["FAKE_VERIFY_MODE"]
output = Path(sys.argv[sys.argv.index("--output") + 1])
output.parent.mkdir(parents=True, exist_ok=True)
if mode == "missing":
    raise SystemExit(1)
if mode == "invalid":
    output.write_text("{", encoding="utf-8")
    raise SystemExit(1)
if mode == "success":
    payload, code = {"passed": True, "findings": []}, 0
elif mode == "denied":
    payload, code = {"passed": False, "findings": [{"code": "POLICY-DENY"}]}, 1
elif mode == "verifier-error":
    payload, code = {"passed": False, "error": {"type": "FakeError"}}, 1
elif mode == "inconsistent":
    payload, code = {"passed": False, "findings": [{"code": "POLICY-DENY"}]}, 0
else:
    raise SystemExit("unknown fake mode")
output.write_text(json.dumps(payload), encoding="utf-8")
raise SystemExit(code)
""",
        encoding="utf-8",
    )

    scenarios = (
        ("success", 0, "success", "success"),
        ("denied", 0, "failure", "denied"),
        ("verifier-error", 1, "failure", "error"),
        ("missing", 1, "failure", "error"),
        ("invalid", 1, "failure", "error"),
        ("inconsistent", 1, "failure", "error"),
    )
    program = _verification_program()
    for mode, expected_returncode, expected_result, expected_outcome in scenarios:
        output = tmp_path / f"github-output-{mode}.txt"
        evidence = tmp_path / "artifacts/trust-refresh/trust-root-verification.json"
        if evidence.exists():
            evidence.unlink()
        env = os.environ.copy()
        env.update(
            {
                "FAKE_VERIFY_MODE": mode,
                "HEAD_SHA": "a" * 40,
                "BASE_SHA": "b" * 40,
                "BASE_REF": "main",
                "MERGE_SHA": "c" * 40,
                "REPOSITORY": "safal207/Causal-Memory-Layer",
                "PULL_NUMBER": "325",
                "GITHUB_RUN_ID": "123",
                "GITHUB_RUN_ATTEMPT": "1",
                "STATUS_CONTEXT": "CML Trust Root Gate / test",
                "GITHUB_OUTPUT": str(output),
            }
        )
        completed = subprocess.run(
            [sys.executable, "-c", program],
            cwd=tmp_path,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert (completed.returncode == 0) == (expected_returncode == 0), (
            mode,
            completed.stdout,
            completed.stderr,
        )
        outputs = dict(
            line.split("=", 1)
            for line in output.read_text(encoding="utf-8").splitlines()
        )
        assert outputs["result"] == expected_result
        assert outputs["outcome"] == expected_outcome
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        assert payload["refresh_outcome"] == expected_outcome
