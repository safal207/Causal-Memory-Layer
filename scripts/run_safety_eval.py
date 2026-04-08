from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cml.safety_eval import render_markdown_report, render_text_report, run_safety_eval


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the CML safety-eval benchmark.")
    parser.add_argument(
        "--fixtures-root",
        default="benchmarks/fixtures",
        help="Path to benchmark fixture directory (default: benchmarks/fixtures)",
    )
    parser.add_argument(
        "--markdown-out",
        help="Optional path to write a Markdown report snapshot.",
    )
    args = parser.parse_args()

    results, summary = run_safety_eval(Path(args.fixtures_root))
    print(render_text_report(results, summary))

    if args.markdown_out:
        out_path = Path(args.markdown_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(render_markdown_report(results, summary), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()