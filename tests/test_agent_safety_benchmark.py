from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cml.agent_safety_benchmark import (
    load_benchmark,
    load_submission,
    render_json_report,
    render_markdown_report,
    run_benchmark,
    score_case,
)

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "benchmarks/agent_safety/benchmark.json"
REFERENCE = ROOT / "benchmarks/agent_safety/reference_submission.json"
UNSAFE = ROOT / "benchmarks/agent_safety/unsafe_submission.json"


def test_benchmark_loads_ten_scenarios_and_mcp_source() -> None:
    raw, scenarios = load_benchmark(BENCHMARK)
    assert raw["version"] == "0.1.0"
    assert len(scenarios) == 10
    assert [item["case_id"] for item in scenarios] == [
        f"ASB-{index:02d}" for index in range(1, 11)
    ]
    assert scenarios[0]["source_artifact"]["required_episode_ids"] == [
        "mcp_sdk_duplicate_diverged",
        "mcp_sdk_duplicate_recovered",
    ]


def test_reference_policy_scores_100_and_matches_snapshots() -> None:
    results, summary = run_benchmark(BENCHMARK, REFERENCE)
    assert summary.total_cases == 10
    assert summary.passed_cases == 10
    assert summary.failed_cases == 0
    assert summary.overall_score == 100.0
    assert summary.critical_failures == 0
    assert all(value == 100.0 for value in summary.dimension_scores.values())
    assert render_markdown_report(results, summary) == (
        ROOT / "benchmarks/agent_safety/RESULTS.md"
    ).read_text(encoding="utf-8")
    assert render_json_report(results, summary) == (
        ROOT / "benchmarks/agent_safety/results.json"
    ).read_text(encoding="utf-8")


def test_unsafe_tool_success_baseline_fails_every_case() -> None:
    results, summary = run_benchmark(BENCHMARK, UNSAFE)
    assert summary.passed_cases == 0
    assert summary.failed_cases == 10
    assert summary.overall_score == 20.0
    assert summary.critical_failures == 20
    assert all(item.final_score == 20 for item in results)
    assert all(
        any(code.startswith("forbidden_action:") for code in item.critical_failures)
        for item in results
    )


def test_critical_failure_caps_an_otherwise_high_score() -> None:
    _, scenarios = load_benchmark(BENCHMARK)
    submission = load_submission(REFERENCE)
    case = dict(submission["cases"][0])
    case["actions"] = case["actions"] + ["create_third_payment"]
    result = score_case(scenarios[0], case, 80)
    assert result.raw_score == 90
    assert result.final_score == 49
    assert not result.passed
    assert result.critical_failures == ("forbidden_action:create_third_payment",)


def test_submission_requires_exact_case_coverage(tmp_path: Path) -> None:
    payload = json.loads(REFERENCE.read_text(encoding="utf-8"))
    payload["cases"] = payload["cases"][:-1]
    path = tmp_path / "submission.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="coverage mismatch"):
        run_benchmark(BENCHMARK, path)


def test_json_schemas_are_strict_draft_2020_12_documents() -> None:
    for name in ("benchmark.schema.json", "submission.schema.json"):
        schema = json.loads(
            (ROOT / "benchmarks/agent_safety" / name).read_text(encoding="utf-8")
        )
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["additionalProperties"] is False


def test_cli_returns_nonzero_for_unsafe_baseline() -> None:
    command = [
        sys.executable,
        "scripts/run_agent_safety_benchmark.py",
        "--submission",
        "benchmarks/agent_safety/unsafe_submission.json",
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 1
    assert "passed=0/10" in completed.stdout


def test_cli_scores_single_case_fragment(tmp_path: Path) -> None:
    reference = json.loads(REFERENCE.read_text(encoding="utf-8"))
    fragment = tmp_path / "asb-01-submission-case.json"
    fragment.write_text(
        json.dumps(reference["cases"][0], indent=2), encoding="utf-8"
    )
    command = [
        sys.executable,
        "scripts/run_agent_safety_benchmark.py",
        "--case",
        "ASB-01",
        "--submission",
        str(fragment),
        "--agent",
        "proofpath-payment-guard",
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert "agent=proofpath-payment-guard" in completed.stdout
    assert "passed=1/1" in completed.stdout
    assert "ASB-01: PASS score=100" in completed.stdout


def test_cli_selects_one_case_from_full_submission() -> None:
    command = [
        sys.executable,
        "scripts/run_agent_safety_benchmark.py",
        "--case",
        "ASB-01",
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert "passed=1/1" in completed.stdout
    assert "ASB-01: PASS score=100" in completed.stdout


def test_cli_rejects_mismatched_case_fragment(tmp_path: Path) -> None:
    reference = json.loads(REFERENCE.read_text(encoding="utf-8"))
    fragment = tmp_path / "asb-01-submission-case.json"
    fragment.write_text(
        json.dumps(reference["cases"][0], indent=2), encoding="utf-8"
    )
    command = [
        sys.executable,
        "scripts/run_agent_safety_benchmark.py",
        "--case",
        "ASB-02",
        "--submission",
        str(fragment),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode != 0
    assert "does not match requested ASB-02" in completed.stderr
