# Large-trace Performance Benchmark Results

This benchmark gives deterministic synthetic evidence for the current in-memory CML `AuditEngine`.

It is not a production capacity claim.

## Purpose

The benchmark answers a narrow engineering question:

```text
How does the current in-memory AuditEngine behave on synthetic traces of 1k / 10k / 50k CML records?
```

## Run locally

```bash
python benchmarks/performance/run_large_trace_benchmark.py
```

Custom sizes:

```bash
python benchmarks/performance/run_large_trace_benchmark.py --sizes 1000 10000 50000 --repeats 3
```

Generate a JSONL trace:

```bash
python benchmarks/performance/generate_large_trace.py --records 10000 --missing-parent-every 997 --output large-trace.jsonl
```

## Synthetic trace design

The generator creates mostly valid causal chains with periodic intentionally broken parent references.

- Record `0` is a valid root event.
- Most records point to the previous record.
- Every `N` records, a record points to a missing parent id.
- This deterministically exercises `CML-AUDIT-R1-MISSING_PARENT`.

Default:

```text
missing_parent_every = 997
```

Expected R1 count:

```text
(total_records - 1) // missing_parent_every
```

## GitHub Actions

The repository includes a workflow:

```text
.github/workflows/large-trace-performance.yml
```

It runs:

```bash
python benchmarks/performance/run_large_trace_benchmark.py --sizes 1000 10000 50000 --repeats 3
```

## Interpreting results

The generated benchmark table reports:

- record count,
- expected R1 findings,
- actual R1 findings,
- total failures,
- warnings,
- median runtime,
- records per second,
- pass/fail status.

A pass means:

```text
actual R1 findings == deterministic expected R1 findings
```

## Scope boundary

This benchmark is a first reproducible performance-evidence layer for CML reviewers and contributors.

It does not claim hosted deployment readiness, distributed tracing support, or graph database integration.
