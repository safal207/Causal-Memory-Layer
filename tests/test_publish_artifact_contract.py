"""Static publishing-contract controls; not a live artifact or publishing proof."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/publish-python-package.yml"
MANIFEST = ".github/trust-root/protected_files.json"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
ARTIFACT = {"name": "python-package-distributions", "path": "dist/"}
PERMISSIONS = {"contents": "read", "id-token": "write"}


class UniqueBaseLoader(yaml.BaseLoader):
    """Preserve GitHub's `on` key and reject duplicate mapping keys."""

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("duplicate or non-string workflow key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_workflow(text: str) -> dict[str, Any]:
    document = yaml.load(text, Loader=UniqueBaseLoader)
    if not isinstance(document, dict):
        raise ValueError("workflow must contain a mapping")
    return document


def assert_publish_contract(document: dict[str, Any]) -> None:
    """Require the reviewed contract without additional execution controls."""
    assert set(document) == {"name", "on", "permissions", "jobs"}
    assert document["name"] == "Publish Python Package"
    assert document["on"] == {
        "workflow_dispatch": {"inputs": {"target": {
            "description": "Publishing target", "required": "true",
            "default": "testpypi", "type": "choice", "options": ["testpypi", "pypi"],
        }}},
        "release": {"types": ["published"]},
    }
    assert document["permissions"] == PERMISSIONS
    jobs = document["jobs"]
    assert set(jobs) == {"build", "publish-testpypi", "publish-pypi"}
    assert jobs["build"] == {
        "name": "Build and validate distributions",
        "runs-on": "ubuntu-latest", "timeout-minutes": "15",
        "steps": [
            {"name": "Checkout repository", "uses": "actions/checkout@v6"},
            {"name": "Setup Python", "uses": "actions/setup-python@v6", "with": {"python-version": "3.11"}},
            {"name": "Install build tools", "run": "python -m pip install --upgrade pip build twine"},
            {"name": "Install package with dev extras", "run": 'pip install -e ".[dev]"'},
            {"name": "Run tests", "run": "pytest"},
            {"name": "Run deterministic safety benchmark", "run": "python scripts/run_safety_eval.py"},
            {"name": "Build source and wheel distributions", "run": "python -m build"},
            {"name": "Validate package metadata", "run": "python -m twine check dist/*"},
            {"name": "Upload distributions artifact", "uses": UPLOAD, "with": ARTIFACT},
        ],
    }
    for target, display, guard, project_url in (
        ("testpypi", "TestPyPI", "github.event_name == 'workflow_dispatch' && inputs.target == 'testpypi'",
         "https://test.pypi.org/project/causal-memory-layer/"),
        ("pypi", "PyPI", "github.event_name == 'release' || (github.event_name == 'workflow_dispatch' && inputs.target == 'pypi')",
         "https://pypi.org/project/causal-memory-layer/"),
    ):
        publisher_inputs = {"print-hash": "true"}
        if target == "testpypi":
            publisher_inputs["repository-url"] = "https://test.pypi.org/legacy/"
        publisher_name = ("Publish package distributions to TestPyPI" if target == "testpypi"
                          else "Publish package distributions to PyPI")
        assert jobs[f"publish-{target}"] == {
            "name": f"Publish distributions to {display}",
            "needs": "build", "if": guard,
            "runs-on": "ubuntu-latest", "timeout-minutes": "10",
            "environment": {"name": target, "url": project_url},
            "permissions": PERMISSIONS,
            "steps": [
                {"name": "Download distributions artifact", "uses": DOWNLOAD, "with": ARTIFACT},
                {"name": publisher_name, "uses": "pypa/gh-action-pypi-publish@release/v1", "with": publisher_inputs},
            ],
        }


def test_reviewed_publish_contract() -> None:
    assert_publish_contract(load_workflow((ROOT / WORKFLOW).read_text(encoding="utf-8")))


@pytest.mark.parametrize("relative", [WORKFLOW, "tests/test_publish_artifact_contract.py"])
def test_manifest_binds_publish_contract(relative: str) -> None:
    manifest = json.loads((ROOT / MANIFEST).read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "cml-trust-root-files-v1"
    data = (ROOT / relative).read_bytes()
    identity = hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data, usedforsecurity=False
    ).hexdigest()
    assert manifest["files"][relative] == identity


@pytest.mark.parametrize(("path", "value"), [
    (("jobs", "build", "steps", 8, "uses"), "actions/upload-artifact@v7"),
    (("jobs", "publish-pypi", "steps", 0, "uses"), "actions/download-artifact@v8"),
    (("jobs", "publish-testpypi", "steps", 0, "uses"), "actions/download-artifact@v4"),
    (("jobs", "build", "steps", 8, "with", "archive"), "false"),
    (("jobs", "build", "steps", 8, "with", "name"), "other-distributions"),
    (("jobs", "publish-pypi", "steps", 0, "with", "name"), "other-distributions"),
    (("jobs", "publish-pypi", "steps", 0, "with", "path"), "other/"),
    (("jobs", "publish-pypi", "steps", 0, "with", "digest-mismatch"), "warn"),
    (("jobs", "publish-pypi", "steps", 0, "with", "skip-decompress"), "true"),
    (("jobs", "publish-pypi", "steps", 0, "with", "run-id"), "1"),
    (("jobs", "publish-pypi", "steps", 0, "with", "repository"), "other/repo"),
    (("jobs", "build", "steps", 4, "run"), "echo tests skipped"),
    (("jobs", "build", "steps", 4, "continue-on-error"), "true"),
    (("jobs", "build", "steps", 5, "run"), "echo benchmark skipped"),
    (("jobs", "build", "steps", 7, "run"), "echo validation skipped"),
    (("jobs", "publish-pypi", "needs"), []),
    (("jobs", "publish-pypi", "if"), "true"),
    (("jobs", "publish-testpypi", "if"), "true"),
    (("jobs", "publish-pypi", "environment", "name"), "unreviewed"),
    (("jobs", "publish-pypi", "permissions", "contents"), "write"),
    (("permissions", "statuses"), "write"),
    (("on", "pull_request"), {}),
    (("jobs", "publish-pypi", "steps", 1, "with", "print-hash"), "false"),
    (("jobs", "publish-pypi", "steps", 0, "continue-on-error"), "true"),
])
def test_unreviewed_contract_changes_are_rejected(path: tuple[Any, ...], value: Any) -> None:
    document = copy.deepcopy(load_workflow((ROOT / WORKFLOW).read_text(encoding="utf-8")))
    parent = document
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(AssertionError):
        assert_publish_contract(document)


def test_duplicate_yaml_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        load_workflow("on: {}\non: {pull_request: {}}\n")
