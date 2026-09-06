from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cml.agent_safety_benchmark import (
    BenchmarkSummary,
    load_benchmark,
    load_submission,
    render_json_report,
    render_markdown_report,
    render_text_report,
    run_benchmark,
    score_case,
)

SUBMISSION_PROFILE = "org.causal-memory-layer.agent-safety-submission"


def _single_case_summary(
    result: Any, *, benchmark_version: str, agent: str
) -> BenchmarkSummary:
    return BenchmarkSummary(
        benchmark_version=benchmark_version,
        agent=agent,
        total_cases=1,
        passed_cases=1 if result.passed else 0,
        failed_cases=0 if result.passed else 1,
        overall_score=float(result.final_score),
        dimension_scores={
            "intent": round(result.intent / 20 * 100, 2),
            "causal_reconstruction": round(
                result.causal_reconstruction / 25 * 100, 2
            ),
            "containment": round(result.containment / 25 * 100, 2),
            "recovery": round(result.recovery / 20 * 100, 2),
            "verification": round(result.verification / 10 * 100, 2),
        },
        critical_failures=len(result.critical_failures),
    )


def _load_single_case(
    submission_path: Path,
    *,
    case_id: str,
    benchmark_version: str,
    agent_override: str | None,
) -> tuple[dict[str, Any], str]:
    raw = json.loads(submission_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("single-case submission must be a JSON object")

    if raw.get("profile") == SUBMISSION_PROFILE:
        submission = load_submission(submission_path)
        if submission["benchmark_version"] != benchmark_version:
            raise ValueError(
                "submission benchmark_version does not match benchmark.version"
            )
        cases = {case["case_id"]: case for case in submission["cases"]}
        if case_id not in cases:
            raise ValueError(f"submission does not contain requested case: {case_id}")
        if agent_override is not None and agent_override != submission["agent"]:
            raise ValueError(
                "agent override does not match submission.agent "
                f"({agent_override!r} != {submission['agent']!r})"
            )
        return cases[case_id], submission["agent"]

    agent = agent_override or f"single-case:{submission_path.stem}"
    envelope = {
        "profile": SUBMISSION_PROFILE,
        "benchmark_version": benchmark_version,
        "agent": agent,
        "cases": [raw],
    }
    with TemporaryDirectory(prefix="cml-asb-") as temporary_directory:
        envelope_path = Path(temporary_directory) / "submission.json"
        envelope_path.write_text(
            json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8"
        )
        submission = load_submission(envelope_path)

    case = submission["cases"][0]
    if case["case_id"] != case_id:
        raise ValueError(
            f"submission case_id {case['case_id']} does not match requested {case_id}"
        )
    return case, agent


def _run_single_case(
    benchmark_path: Path,
    submission_path: Path,
    *,
    case_id: str,
    agent: str | None,
) -> tuple[list[Any], BenchmarkSummary]:
    benchmark, scenarios = load_benchmark(benchmark_path)
    scenario_by_id = {scenario["case_id"]: scenario for scenario in scenarios}
    if case_id not in scenario_by_id:
        raise ValueError(f"unknown benchmark case: {case_id}")

    case, resolved_agent = _load_single_case(
        submission_path,
        case_id=case_id,
        benchmark_version=benchmark["version"],
        agent_override=agent,
    )
    result = score_case(
        scenario_by_id[case_id], case, benchmark["pass_threshold"]
    )
    summary = _single_case_summary(
        result,
        benchmark_version=benchmark["version"],
        agent=resolved_agent,
    )
    return [result], summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run CML Agent Safety Benchmark v0.1."
    )
    parser.add_argument(
        "--benchmark",
        default="benchmarks/agent_safety/benchmark.json",
        help="Benchmark definition JSON.",
    )
    parser.add_argument(
        "--submission",
        default="benchmarks/agent_safety/reference_submission.json",
        help=(
            "Agent submission JSON. With --case, this may be either a full "
            "submission envelope or one strict case fragment."
        ),
    )
    parser.add_argument(
        "--case",
        dest="case_id",
        help="Run only one benchmark case, for example ASB-01.",
    )
    parser.add_argument(
        "--agent",
        help="Agent label for a case fragment. Only used with --case.",
    )
    parser.add_argument("--markdown-out", help="Optional Markdown report path.")
    parser.add_argument("--json-out", help="Optional machine-readable report path.")
    args = parser.parse_args()

    if args.agent and not args.case_id:
        parser.error("--agent requires --case")

    benchmark_path = Path(args.benchmark)
    submission_path = Path(args.submission)
    if args.case_id:
        results, summary = _run_single_case(
            benchmark_path,
            submission_path,
            case_id=args.case_id,
            agent=args.agent,
        )
    else:
        results, summary = run_benchmark(benchmark_path, submission_path)

    print(render_text_report(results, summary))
    if args.markdown_out:
        path = Path(args.markdown_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            render_markdown_report(results, summary),
            encoding="utf-8",
            newline="\n",
        )
    if args.json_out:
        path = Path(args.json_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            render_json_report(results, summary),
            encoding="utf-8",
            newline="\n",
        )
    return 0 if summary.failed_cases == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
