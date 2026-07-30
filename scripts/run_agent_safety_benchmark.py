from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cml.agent_safety_benchmark import (
    render_json_report,
    render_markdown_report,
    render_text_report,
    run_benchmark,
)


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
        help="Agent submission JSON.",
    )
    parser.add_argument("--markdown-out", help="Optional Markdown report path.")
    parser.add_argument("--json-out", help="Optional machine-readable report path.")
    args = parser.parse_args()

    results, summary = run_benchmark(Path(args.benchmark), Path(args.submission))
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
