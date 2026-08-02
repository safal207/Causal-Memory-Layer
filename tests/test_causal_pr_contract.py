from __future__ import annotations

from pathlib import Path

from scripts.ci.build_causal_pr_report import (
    Change,
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
A stale transition could reach main without a test that reproduces the failure.

### Invariant after change
Every strict transition is bound to one exact head and regression evidence.

### Regression evidence
Added `tests/test_causal_pr_contract.py` to exercise the policy and failure paths.

### Residual risk
External reviewers remain independent required checks rather than merge authority.
"""


def _evaluate(
    tmp_path: Path,
    changes: list[Change],
    body: str = COMPLETE_BODY,
):
    return evaluate_transition(
        repo_root=tmp_path,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        changes=changes,
        body=body,
        current_head=HEAD_SHA,
        dirty=False,
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
    assert report["groups"]["implementation"] == ["cml/audit.py"]
    assert report["groups"]["tests"] == ["tests/test_causal_pr_contract.py"]


def test_strict_transition_rejects_missing_causal_sections(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [Change("M", "api/server.py"), Change("M", "tests/test_api_smoke.py")],
        body="## Summary\nChanged the API.",
    )

    assert report["passed"] is False
    assert any("missing causal review section" in item for item in report["violations"])


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


def test_implementation_change_without_test_evidence_fails(tmp_path: Path) -> None:
    body = COMPLETE_BODY.replace(
        "Added `tests/test_causal_pr_contract.py` to exercise the policy and failure paths.",
        "Manually inspected the change.",
    )

    report = _evaluate(tmp_path, [Change("M", "cli/main.py")], body=body)

    assert any(
        "require changed tests or explicit existing test paths" in item
        for item in report["violations"]
    )


def test_workflow_change_requires_contract_regression_test(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", ".github/workflows/ci.yml"),
            Change("M", "tests/test_api_smoke.py"),
        ],
    )

    assert any(
        "workflow contract changes require" in item for item in report["violations"]
    )


def test_workflow_change_with_contract_test_passes(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [
            Change("M", ".github/workflows/ci.yml"),
            Change("M", "tests/test_ci_workflow_contract.py"),
        ],
    )

    assert report["passed"] is True, report["violations"]


def test_documentation_only_transition_is_lightweight(tmp_path: Path) -> None:
    report = _evaluate(
        tmp_path,
        [Change("M", "docs/architecture.md")],
        body="",
    )

    assert report["passed"] is True
    assert report["scope"] == "lightweight"


def test_placeholder_sections_fail_closed(tmp_path: Path) -> None:
    body = COMPLETE_BODY.replace(
        "A stale transition could reach main without a test that reproduces the failure.",
        "TODO",
    )
    report = _evaluate(
        tmp_path,
        [Change("M", "scripts/ci/tool.py"), Change("M", "tests/test_tool.py")],
        body=body,
    )

    assert any("contains a placeholder: failure_path" in item for item in report["violations"])


def test_placeholder_word_inside_real_explanation_is_allowed(tmp_path: Path) -> None:
    body = COMPLETE_BODY.replace(
        "Every strict transition is bound to one exact head and regression evidence.",
        "Every strict transition requires completed, non-placeholder causal sections.",
    )
    report = _evaluate(
        tmp_path,
        [
            Change("M", "scripts/ci/tool.py"),
            Change("M", "tests/test_causal_pr_contract.py"),
        ],
        body=body,
    )

    assert report["passed"] is True, report["violations"]


def test_rename_is_classified_by_destination_path() -> None:
    groups = classify_changes(
        [Change("R100", "tests/test_new_name.py", "tests/test_old_name.py")]
    )

    assert groups["tests"] == ["tests/test_new_name.py"]


def test_markdown_report_contains_causal_graph_without_raw_url(tmp_path: Path) -> None:
    body = COMPLETE_BODY.replace(
        "Every strict transition is bound to one exact head and regression evidence.",
        "The proof is recorded at https://example.invalid/private.",
    )
    report = _evaluate(
        tmp_path,
        [Change("M", "cml/audit.py"), Change("M", "tests/test_causal_pr_contract.py")],
        body=body,
    )

    markdown = render_markdown(report)

    assert "flowchart LR" in markdown
    assert "https://example.invalid/private" not in markdown
    assert "[URL]" in markdown


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
