from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cml.agent_safety_benchmark import (
    BenchmarkSummary,
    load_benchmark,
    render_json_report,
    render_markdown_report,
    render_text_report,
    score_case,
)
from cml.proofpath_asb01_evidence import CASE_ID, derive_asb01_case


def _summary(result: object, *, benchmark_version: str, agent: str) -> BenchmarkSummary:
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
                result.causal_reconstruction / 25 * 100,
                2,
            ),
            "containment": round(result.containment / 25 * 100, 2),
            "recovery": round(result.recovery / 20 * 100, 2),
            "verification": round(result.verification / 10 * 100, 2),
        },
        critical_failures=len(result.critical_failures),
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Independently derive and score CML ASB-01 from a self-contained "
            "ProofPath evidence bundle."
        )
    )
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument(
        "--benchmark",
        default="benchmarks/agent_safety/benchmark.json",
    )
    parser.add_argument("--agent", default="proofpath-asb01-evidence")
    parser.add_argument("--derived-case-out")
    parser.add_argument("--markdown-out")
    parser.add_argument("--json-out")
    args = parser.parse_args()

    derived_case = derive_asb01_case(Path(args.evidence_dir))
    benchmark, scenarios = load_benchmark(Path(args.benchmark))
    scenario_by_id = {scenario["case_id"]: scenario for scenario in scenarios}
    result = score_case(
        scenario_by_id[CASE_ID],
        derived_case,
        benchmark["pass_threshold"],
    )
    summary = _summary(
        result,
        benchmark_version=benchmark["version"],
        agent=args.agent,
    )

    print(render_text_report([result], summary))
    if args.derived_case_out:
        path = Path(args.derived_case_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(derived_case, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if args.markdown_out:
        path = Path(args.markdown_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            render_markdown_report([result], summary),
            encoding="utf-8",
            newline="\n",
        )
    if args.json_out:
        path = Path(args.json_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            render_json_report([result], summary),
            encoding="utf-8",
            newline="\n",
        )
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
