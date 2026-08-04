from __future__ import annotations

import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.ci.build_causal_pr_report import (
    Change,
    _is_executable_test_path,
    build_report,
    changed_files,
    classify_changes,
    evaluate_transition,
    extract_sections,
    render_markdown,
)

BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
COMPLETE_BODY = """
## Causal review

### Failure path
A stale transition could reach a protected branch without a reproducing test.

### Invariant after change
Every strict transition is bound to its exact base, exact head, and regression evidence.

### Regression evidence
Added `tests/test_causal_pr_contract.py` to exercise the policy and failure paths.

### Residual risk
External reviewers remain independent checks rather than merge authority.
"""


def _evaluate(
    tmp_path: Path,
    changes: list[Change],
    body: str = COMPLETE_BODY,
    *,
    base_is_ancestor: bool = True,
):
    normalized_changes: list[Change] = []
    for change in changes:
        candidate = tmp_path / change.path
        normalized = change
        if not change.status.startswith("D") and _is_executable_test_path(change.path):
            if not os.path.lexists(candidate):
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text(
                    "def test_regression():\n    assert True\n", encoding="utf-8"
                )
            if (
                change.mode is None
                and candidate.is_file()
                and not candidate.is_symlink()
            ):
                normalized = replace(change, mode="100644")
        normalized_changes.append(normalized)
    return evaluate_transition(
        repo_root=tmp_path,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        changes=normalized_changes,
        body=body,
        current_head=HEAD_SHA,
        dirty=False,
        base_is_ancestor=base_is_ancestor,
    )


def test_strict_source_transition_with_changed_test_passes(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", "cml/audit.py"),
            Change("A", "tests/test_causal_pr_contract.py"),
        ],
    )
    assert report["passed"] is True, report["violations"]
    assert report["scope"] == "strict"
    assert report["changed_regression_tests"] == [
        "tests/test_causal_pr_contract.py"
    ]


def test_typescript_packaging_and_container_files_are_strict(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", "integrations/vscode-cml/src/extension.ts"),
            Change("M", "integrations/vscode-cml/package.json"),
            Change("M", "Dockerfile"),
            Change("M", "tests/test_causal_pr_contract.py"),
        ],
    )
    assert report["scope"] == "strict"
    assert {
        "integrations/vscode-cml/src/extension.ts",
        "integrations/vscode-cml/package.json",
        "Dockerfile",
    }.issubset(set(report["groups"]["implementation"]))


def test_runtime_suffixes_override_documentation_name_prefixes(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("A", "README.py"),
            Change("A", "LICENSE.js"),
            Change("M", "tests/test_causal_pr_contract.py"),
        ],
    )
    assert report["scope"] == "strict"
    assert {"README.py", "LICENSE.js"}.issubset(
        set(report["groups"]["implementation"])
    )
    assert "README.py" not in report["groups"]["documentation"]
    assert "LICENSE.js" not in report["groups"]["documentation"]


def test_documentation_prefix_requires_exact_filename(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("A", "README-runner"),
            Change("M", "tests/test_causal_pr_contract.py"),
        ],
    )
    assert report["scope"] == "strict"
    assert report["groups"]["other"] == ["README-runner"]
    assert "README-runner" not in report["groups"]["documentation"]


def test_genuine_documentation_names_remain_lightweight(tmp_path: Path) -> None:
    for path in ("README", "LICENSE", "README.md", "docs/architecture.md"):
        report = _evaluate(
            tmp_path,
            [Change("M", path, mode="100644")],
            body="",
        )
        assert report["passed"] is True, (path, report["violations"])
        assert report["scope"] == "lightweight"


@pytest.mark.parametrize("mode", ["120000", "160000"])
def test_non_regular_documentation_entries_are_strict(
    tmp_path: Path, mode: str
) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("A", "README", mode=mode),
            Change("M", "tests/test_causal_pr_contract.py", mode="100644"),
        ],
    )
    assert report["scope"] == "strict"
    assert report["groups"]["documentation"] == []
    assert report["groups"]["implementation"] == ["README"]


def test_unknown_non_documentation_format_fails_closed(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", "assets/runtime-policy.bin"),
            Change("M", "tests/test_causal_pr_contract.py"),
        ],
    )
    assert report["scope"] == "strict"
    assert report["groups"]["other"] == ["assets/runtime-policy.bin"]


def test_script_inside_docs_is_not_documentation(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", "docs/examples/deploy.py"),
            Change("M", "tests/test_causal_pr_contract.py"),
        ],
    )
    assert report["groups"]["implementation"] == ["docs/examples/deploy.py"]


def test_missing_causal_sections_fail(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [Change("M", "api/server.py"), Change("M", "tests/test_api_smoke.py")],
        body="## Summary\nChanged the API.",
    )
    assert report["passed"] is False
    assert any("missing causal review section" in item for item in report["violations"])


def test_duplicate_canonical_section_fails_closed(tmp_path: Path) -> None:
    body = (
        COMPLETE_BODY
        + "\n### Invariant after change\nA second ambiguous invariant must be rejected.\n"
    )
    report = _evaluate(
        tmp_path,
        [
            Change("M", "api/server.py"),
            Change("M", "tests/test_causal_pr_contract.py"),
        ],
        body=body,
    )
    assert report["passed"] is False
    assert "duplicate causal review section: invariant" in report["violations"]
    assert report["sections"]["invariant"]["summary"].startswith(
        "Every strict transition"
    )


def test_existing_regression_test_reference_can_satisfy_contract(tmp_path: Path) -> None:
    existing = tmp_path / "tests" / "test_existing_contract.py"
    existing.parent.mkdir(parents=True)
    existing.write_text("def test_existing():\n    assert True\n", encoding="utf-8")
    body = COMPLETE_BODY.replace(
        "Added `tests/test_causal_pr_contract.py` to exercise the policy and failure paths.",
        "Existing test: `tests/test_existing_contract.py` exercises this invariant.",
    )
    report = _evaluate(tmp_path, [Change("M", "cml/record.py")], body=body)
    assert report["passed"] is True, report["violations"]
    assert report["existing_test_references"] == ["tests/test_existing_contract.py"]


def test_regression_reference_cannot_escape_repository(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.py"
    outside.write_text("def test_outside():\n    assert True\n", encoding="utf-8")
    body = COMPLETE_BODY.replace(
        "Added `tests/test_causal_pr_contract.py` to exercise the policy and failure paths.",
        "Existing test: `tests/../../outside.py` exercises this invariant.",
    )
    report = _evaluate(tmp_path, [Change("M", "cml/record.py")], body=body)
    assert report["existing_test_references"] == []
    assert any("surviving executable" in item for item in report["violations"])


def test_strict_change_without_test_evidence_fails(tmp_path: Path) -> None:
    body = COMPLETE_BODY.replace(
        "Added `tests/test_causal_pr_contract.py` to exercise the policy and failure paths.",
        "Manually inspected the change.",
    )
    report = _evaluate(tmp_path, [Change("M", "cli/main.py")], body=body)
    assert any("surviving executable" in item for item in report["violations"])


@pytest.mark.parametrize(
    "test_change",
    [
        Change("D", "tests/test_old.py", previous_mode="100644"),
        Change("A", "tests/README.md", mode="100644"),
        Change(
            "R100",
            "tests/README.md",
            "tests/test_old.py",
            mode="100644",
            previous_mode="100644",
        ),
    ],
)
def test_non_runnable_test_change_does_not_satisfy_regression_contract(
    tmp_path: Path, test_change: Change
) -> None:
    report = _evaluate(
        tmp_path,
        [Change("M", "cml/record.py"), test_change],
    )
    assert report["passed"] is False
    assert report["changed_regression_tests"] == []
    assert any("surviving executable" in item for item in report["violations"])


def test_symlink_test_destination_does_not_satisfy_regression_contract(
    tmp_path: Path,
) -> None:
    symlink = tmp_path / "tests" / "test_regression.py"
    symlink.parent.mkdir(parents=True)
    symlink.symlink_to("/dev/null")
    report = _evaluate(
        tmp_path,
        [
            Change("M", "cml/record.py"),
            Change("A", "tests/test_regression.py", mode="120000"),
        ],
    )
    assert report["passed"] is False
    assert report["changed_regression_tests"] == []
    assert any("surviving executable" in item for item in report["violations"])


def test_symlink_existing_test_reference_does_not_satisfy_contract(
    tmp_path: Path,
) -> None:
    real = tmp_path / "tests" / "test_real.py"
    real.parent.mkdir(parents=True)
    real.write_text("def test_real():\n    assert True\n", encoding="utf-8")
    alias = tmp_path / "tests" / "test_alias.py"
    alias.symlink_to(real.name)
    body = COMPLETE_BODY.replace(
        "Added `tests/test_causal_pr_contract.py` to exercise the policy and failure paths.",
        "Existing test: `tests/test_alias.py` exercises this invariant.",
    )
    report = _evaluate(tmp_path, [Change("M", "cml/record.py")], body=body)
    assert report["passed"] is False
    assert report["existing_test_references"] == []
    assert any("surviving executable" in item for item in report["violations"])


def test_symlinked_ancestor_test_reference_does_not_satisfy_contract(
    tmp_path: Path,
) -> None:
    target = tmp_path / "docs" / "not_a_test.py"
    target.parent.mkdir(parents=True)
    target.write_text("VALUE = 1\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "alias").symlink_to("../docs", target_is_directory=True)
    body = COMPLETE_BODY.replace(
        "Added `tests/test_causal_pr_contract.py` to exercise the policy and failure paths.",
        "Existing test: `tests/alias/not_a_test.py` exercises this invariant.",
    )
    report = _evaluate(tmp_path, [Change("M", "cml/record.py")], body=body)
    assert report["passed"] is False
    assert report["existing_test_references"] == []
    assert any("surviving executable" in item for item in report["violations"])


def test_gitlink_mode_test_destination_does_not_satisfy_contract(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "tests" / "test_submodule.py"
    destination.mkdir(parents=True)
    report = _evaluate(
        tmp_path,
        [
            Change("M", "cml/record.py"),
            Change("A", "tests/test_submodule.py", mode="160000"),
        ],
    )
    assert report["passed"] is False
    assert report["changed_regression_tests"] == []


def test_surviving_executable_test_satisfies_regression_contract(
    tmp_path: Path,
) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", "cml/record.py"),
            Change("M", "tests/test_record.py", mode="100644"),
        ],
    )
    assert report["passed"] is True, report["violations"]
    assert report["changed_regression_tests"] == ["tests/test_record.py"]


def test_regular_executable_test_blob_satisfies_regression_contract(
    tmp_path: Path,
) -> None:
    test_file = tmp_path / "tests" / "test_cli.sh"
    test_file.parent.mkdir(parents=True)
    test_file.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    test_file.chmod(0o755)
    report = _evaluate(
        tmp_path,
        [
            Change("M", "cml/record.py"),
            Change("A", "tests/test_cli.sh", mode="100755"),
        ],
    )
    assert report["passed"] is True, report["violations"]
    assert report["changed_regression_tests"] == ["tests/test_cli.sh"]


def test_rename_destination_executable_test_satisfies_contract(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", "cml/record.py"),
            Change(
                "R100",
                "tests/test_record_new.py",
                "tests/README.md",
                mode="100644",
                previous_mode="100644",
            ),
        ],
    )
    assert report["passed"] is True, report["violations"]
    assert report["changed_regression_tests"] == ["tests/test_record_new.py"]


def test_workflow_change_requires_contract_test(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", ".github/workflows/ci.yml"),
            Change("M", "tests/test_api_smoke.py", mode="100644"),
        ],
    )
    assert any("workflow contract changes require" in item for item in report["violations"])


def test_deleted_workflow_contract_test_does_not_satisfy_contract(
    tmp_path: Path,
) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", ".github/workflows/ci.yml"),
            Change(
                "D",
                "tests/test_ci_workflow_contract.py",
                previous_mode="100644",
            ),
        ],
    )
    assert any("workflow contract changes require" in item for item in report["violations"])


def test_workflow_change_with_contract_test_passes(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", ".github/workflows/ci.yml"),
            Change("M", "tests/test_ci_workflow_contract.py", mode="100644"),
        ],
    )
    assert report["passed"] is True, report["violations"]


def test_placeholder_sections_fail_closed(tmp_path: Path) -> None:
    body = COMPLETE_BODY.replace(
        "A stale transition could reach a protected branch without a reproducing test.",
        "TODO",
    )
    report = _evaluate(
        tmp_path,
        [
            Change("M", "scripts/ci/tool.py"),
            Change("M", "tests/test_tool.py", mode="100644"),
        ],
        body=body,
    )
    assert any("contains a placeholder: failure_path" in item for item in report["violations"])


def test_placeholder_word_inside_real_explanation_is_allowed(tmp_path: Path) -> None:
    body = COMPLETE_BODY.replace(
        "Every strict transition is bound to its exact base, exact head, and regression evidence.",
        "Every strict transition requires completed, non-placeholder causal sections.",
    )
    report = _evaluate(
        tmp_path,
        [
            Change("M", "scripts/ci/tool.py"),
            Change("M", "tests/test_causal_pr_contract.py", mode="100644"),
        ],
        body=body,
    )
    assert report["passed"] is True, report["violations"]


def test_rename_classifies_source_and_destination_paths() -> None:
    groups = classify_changes(
        [
            Change(
                "R100",
                "docs/deploy.md",
                "scripts/deploy.py",
                mode="100644",
                previous_mode="100644",
            )
        ]
    )
    assert groups["documentation"] == ["docs/deploy.md"]
    assert groups["implementation"] == ["scripts/deploy.py"]


def test_rename_from_runtime_to_docs_remains_strict(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change(
                "R100",
                "docs/deploy.md",
                "scripts/deploy.py",
                mode="100644",
                previous_mode="100644",
            ),
            Change("M", "tests/test_causal_pr_contract.py", mode="100644"),
        ],
    )
    assert report["scope"] == "strict"
    assert report["changes"][0]["previous_path"] == "scripts/deploy.py"


def test_non_ancestor_transition_fails_closed(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [Change("M", "tests/test_causal_pr_contract.py", mode="100644")],
        base_is_ancestor=False,
    )
    assert report["passed"] is False
    assert report["base_is_ancestor"] is False
    assert any("not an ancestor" in item for item in report["violations"])


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def test_build_report_rejects_invalid_sha_before_git(tmp_path: Path) -> None:
    event = tmp_path / "event.json"
    with pytest.raises(ValueError, match="base SHA must be"):
        build_report(
            repo_root=tmp_path / "missing-repository",
            base_sha="--output=/tmp/cml-invalid",
            head_sha=HEAD_SHA,
            event_path=event,
        )


def test_build_report_rejects_divergent_base_and_head(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "ci@example.invalid")
    _git(repo, "config", "user.name", "CI")
    (repo / "root.txt").write_text("root\n", encoding="utf-8")
    _git(repo, "add", "root.txt")
    _git(repo, "commit", "-m", "base")
    base0 = _git(repo, "rev-parse", "HEAD")

    _git(repo, "checkout", "-b", "feature", base0)
    (repo / "feature.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "feature.py")
    _git(repo, "commit", "-m", "feature")
    head = _git(repo, "rev-parse", "HEAD")

    _git(repo, "checkout", "main")
    (repo / "main.txt").write_text("advanced\n", encoding="utf-8")
    _git(repo, "add", "main.txt")
    _git(repo, "commit", "-m", "advance base")
    advanced_base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "feature")

    event = tmp_path / "event.json"
    event.write_text(
        json.dumps({"pull_request": {"body": COMPLETE_BODY}}),
        encoding="utf-8",
    )
    report = build_report(
        repo_root=repo,
        base_sha=advanced_base,
        head_sha=head,
        event_path=event,
    )
    assert report["passed"] is False
    assert report["base_is_ancestor"] is False
    assert any("not an ancestor" in item for item in report["violations"])


def test_build_report_accepts_freshly_fetched_real_ancestor(tmp_path: Path) -> None:
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    _git(upstream, "init", "-b", "main")
    _git(upstream, "config", "user.email", "ci@example.invalid")
    _git(upstream, "config", "user.name", "CI")
    (upstream / "README.md").write_text("base\n", encoding="utf-8")
    _git(upstream, "add", "README.md")
    _git(upstream, "commit", "-m", "base")
    base_sha = _git(upstream, "rev-parse", "HEAD")
    (upstream / "README.md").write_text("base\nfeature\n", encoding="utf-8")
    _git(upstream, "add", "README.md")
    _git(upstream, "commit", "-m", "feature docs")
    head_sha = _git(upstream, "rev-parse", "HEAD")

    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "--bare", str(remote))
    _git(upstream, "remote", "add", "origin", str(remote))
    _git(upstream, "push", "origin", "main")

    review = tmp_path / "review"
    review.mkdir()
    _git(review, "init")
    _git(review, "fetch", "--no-tags", str(remote), head_sha)
    _git(review, "checkout", "--detach", "FETCH_HEAD")
    _git(review, "fetch", "--no-tags", str(remote), base_sha)

    event = tmp_path / "fresh-event.json"
    event.write_text(json.dumps({"pull_request": {"body": ""}}), encoding="utf-8")
    report = build_report(
        repo_root=review,
        base_sha=base_sha,
        head_sha=head_sha,
        event_path=event,
    )
    assert report["passed"] is True, report["violations"]
    assert report["base_is_ancestor"] is True
    assert report["scope"] == "lightweight"


def test_changed_files_parses_real_rename_with_exact_paths(tmp_path: Path) -> None:
    repo = tmp_path / "rename-repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "ci@example.invalid")
    _git(repo, "config", "user.name", "CI")
    old_name = "deploy_тест.py"
    new_name = "renamed_тест.py"
    (repo / old_name).write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", old_name)
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    _git(repo, "mv", old_name, new_name)
    _git(repo, "commit", "-m", "rename")
    head = _git(repo, "rev-parse", "HEAD")

    changes = changed_files(repo, base, head)
    assert len(changes) == 1
    assert changes[0].status.startswith("R")
    assert changes[0].previous_path == old_name
    assert changes[0].path == new_name
    assert changes[0].mode == "100644"
    assert changes[0].previous_mode == "100644"


def test_executable_exact_documentation_name_is_strict(tmp_path: Path) -> None:
    repo = tmp_path / "mode-repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "ci@example.invalid")
    _git(repo, "config", "user.name", "CI")
    (repo / "baseline.txt").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "baseline.txt")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    readme = repo / "README"
    readme.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    readme.chmod(0o755)
    _git(repo, "add", "README")
    _git(repo, "commit", "-m", "add executable readme")
    head = _git(repo, "rev-parse", "HEAD")

    changes = changed_files(repo, base, head)
    assert changes[0].mode == "100755"
    groups = classify_changes(changes)
    assert groups["implementation"] == ["README"]
    assert groups["documentation"] == []


def test_markdown_report_contains_graph_without_raw_url(tmp_path: Path) -> None:
    body = COMPLETE_BODY.replace(
        "Every strict transition is bound to its exact base, exact head, and regression evidence.",
        "The proof is recorded at https://example.invalid/private.",
    )
    report = _evaluate(
        tmp_path,
        [
            Change("M", "cml/audit.py"),
            Change("M", "tests/test_causal_pr_contract.py", mode="100644"),
        ],
        body=body,
    )
    markdown = render_markdown(report)
    assert "flowchart LR" in markdown
    assert "https://example.invalid/private" not in markdown
    assert "[URL]" in markdown
    assert "Base is ancestor: `true`" in markdown
    assert "Surviving executable changed tests: `1`" in markdown


def test_extract_sections_accepts_documented_aliases() -> None:
    sections = extract_sections(
        "## Failure mode\nA\n## Target invariant\nB\n"
        "## Regression test\nC\n## Remaining risk\nD\n"
    )
    assert sections == {
        "failure_path": "A",
        "invariant": "B",
        "regression_evidence": "C",
        "residual_risk": "D",
    }
