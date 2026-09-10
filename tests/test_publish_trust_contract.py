from __future__ import annotations

import hashlib
import json
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

    checkout = _named_step(workflow, "Checkout repository")
    assert _mapping(checkout.get("with")).get("persist-credentials") == "false"


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
