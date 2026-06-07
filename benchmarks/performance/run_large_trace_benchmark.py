"""Run deterministic large-trace performance benchmarks for CML AuditEngine.

This benchmark is intentionally simple and dependency-light. It is not a
production scalability claim. It provides reproducible evidence for how the
current in-memory AuditEngine behaves on synthetic traces of different sizes.

Example:

    python benchmarks/performance/run_large_trace_benchmark.py

Custom sizes:

    python benchmarks/performance/run_large_trace_benchmark.py --sizes 1000 10000 50000
"""

from __future__ import annotations

import argparse
import platform
import statistics
import time
from dataclasses import dataclass

from cml.audit import AuditEngine
from benchmarks.performance.generate_large_trace import (
    expected_missing_parent_findings,
    generate_records,
)


@dataclass(frozen=True)
class BenchmarkResult:
    records: int
    missing_parent_every: int
    expected_r1_findings: int
    actual_r1_findings: int
    failures: int
    warnings: int
    passed: bool
    runtime_seconds: float
    records_per_second: float


def run_once(total_records: int, missing_parent_every: int) -> BenchmarkResult:
    records = generate_records(total_records, missing_parent_every)
    expected_r1 = expected_missing_parent_findings(total_records, missing_parent_every)

    start = time.perf_counter()
    result = AuditEngine().run(records)
    runtime = time.perf_counter() - start

    actual_r1 = sum(
        1 for finding in result.findings
        if finding.code == "CML-AUDIT-R1-MISSING_PARENT"
    )

    passed = actual_r1 == expected_r1
    records_per_second = total_records / runtime if runtime > 0 else float("inf")

    return BenchmarkResult(
        records=total_records,
        missing_parent_every=missing_parent_every,
        expected_r1_findings=expected_r1,
        actual_r1_findings=actual_r1,
        failures=result.failures,
        warnings=result.warnings,
        passed=passed,
        runtime_seconds=runtime,
        records_per_second=records_per_second,
    )


def run_repeated(
    total_records: int,
    missing_parent_every: int,
    repeats: int,
) -> BenchmarkResult:
    runs = [run_once(total_records, missing_parent_every) for _ in range(repeats)]
    runtimes = [run.runtime_seconds for run in runs]
    median_runtime = statistics.median(runtimes)
    median_rps = total_records / median_runtime if median_runtime > 0 else float("inf")

    first = runs[0]
    passed = all(run.passed for run in runs)

    return BenchmarkResult(
        records=first.records,
        missing_parent_every=first.missing_parent_every,
        expected_r1_findings=first.expected_r1_findings,
        actual_r1_findings=first.actual_r1_findings,
        failures=first.failures,
        warnings=first.warnings,
        passed=passed,
        runtime_seconds=median_runtime,
        records_per_second=median_rps,
    )


def format_markdown(results: list[BenchmarkResult], repeats: int) -> str:
    lines = [
        "# CML Large-trace Performance Benchmark",
        "",
        "This benchmark is deterministic and synthetic. It is intended as",
        "engineering evidence for the current in-memory `AuditEngine`, not as a",
        "production scalability guarantee.",
        "",
        "## Environment",
        "",
        f"- Python: `{platform.python_version()}`",
        f"- Platform: `{platform.platform()}`",
        f"- Repeats per size: `{repeats}`",
        "",
        "## Results",
        "",
        "| records | expected R1 | actual R1 | failures | warnings | median runtime (s) | records/s | passed |",
        "|---:|---:|---:|---:|---:|---:|---:|:---:|",
    ]

    for result in results:
        lines.append(
            "| "
            f"{result.records} | "
            f"{result.expected_r1_findings} | "
            f"{result.actual_r1_findings} | "
            f"{result.failures} | "
            f"{result.warnings} | "
            f"{result.runtime_seconds:.6f} | "
            f"{result.records_per_second:.0f} | "
            f"{'yes' if result.passed else 'no'} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `expected R1` is derived from the deterministic synthetic trace generator.",
            "- `actual R1` counts `CML-AUDIT-R1-MISSING_PARENT` findings returned by `AuditEngine`.",
            "- The benchmark currently focuses on in-memory reference-integrity behavior.",
            "- Large-scale storage, graph database integration, and distributed trace handling remain future work.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes",
        type=int,
        nargs="+",
        default=[1_000, 10_000, 50_000],
        help="Trace sizes to benchmark.",
    )
    parser.add_argument(
        "--missing-parent-every",
        type=int,
        default=997,
        help="Inject one missing parent reference every N records.",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=3,
        help="Number of repeated runs per size; median runtime is reported.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.repeats < 1:
        raise SystemExit("--repeats must be >= 1")

    results = [
        run_repeated(size, args.missing_parent_every, args.repeats)
        for size in args.sizes
    ]

    print(format_markdown(results, repeats=args.repeats))

    if not all(result.passed for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
