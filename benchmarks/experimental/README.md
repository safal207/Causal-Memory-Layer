# Experimental Benchmark Fixtures

This directory stores benchmark sketches that are intentionally **not** part of the deterministic safety-eval runner yet.

The active safety-eval runner scans `benchmarks/fixtures/*.json` and requires predicted findings to exactly match `expected_codes`. Experimental fixtures live here when the concept is useful but the audit rule is not implemented yet.

Use this area for:

- future audit-rule examples,
- non-normative fixture sketches,
- reviewer-facing examples that should not affect CI,
- early Cause Band / range-drift scenarios.

Promotion path:

1. Keep the scenario here while semantics are unstable.
2. Add evaluator support behind an experimental flag.
3. Move the fixture into `benchmarks/fixtures/` only after the expected finding code is implemented.
