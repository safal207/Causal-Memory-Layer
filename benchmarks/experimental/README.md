# Experimental Benchmark Fixtures

This directory stores benchmark sketches that are intentionally **not** part of the deterministic safety-eval runner yet.

The active safety-eval runner scans `benchmarks/fixtures/*.json` and requires predicted findings to exactly match `expected_codes`. Experimental fixtures live here when the concept is useful but the audit rule is not implemented yet.

Use this area for:

- future audit-rule examples,
- non-normative fixture sketches,
- reviewer-facing examples that should not affect CI,
- early Cause Band / range-drift scenarios.

## Cause Band fixture matrix

Current experimental Cause Band fixtures:

| Fixture | Scenario | Purpose |
| :--- | :--- | :--- |
| `07_range_drift_intent.json` | safe → warning → danger → critical | Baseline degrading trajectory with critical exit. |
| `08_range_recovery_intent.json` | safe → warning → danger → safe | Recovery before persistent deviation threshold. |
| `09_range_oscillation_intent.json` | safe → warning → safe → warning → danger | Oscillation without stable recovery. |
| `10_range_persistent_without_critical.json` | safe → warning → warning → danger | Persistent deviation without critical exit. |

These fixtures are intentionally outside `benchmarks/fixtures/` until Cause Band semantics and findings are promoted beyond experimental status.

## Cause Band evaluator

The experimental Cause Band evaluator can be run manually:

```bash
python scripts/run_experimental_cause_band_eval.py
```

Machine-readable output:

```bash
python scripts/run_experimental_cause_band_eval.py --json
```

The evaluator reports finding codes and trajectory diagnostics.

Finding codes currently remain limited to:

```text
CML-AUDIT-RANGE-DRIFT
CML-AUDIT-RANGE-PERSISTENT_DEVIATION
CML-AUDIT-RANGE-CRITICAL_EXIT
```

Trajectory diagnostics currently include:

```text
trajectory_direction
recovered_to_safe
oscillating
max_consecutive_outside_safe
```

Recovery and oscillation are diagnostics only for now. They are not promoted to standalone `CML-AUDIT-RANGE-*` finding codes until severity and audit-result semantics are stable.

The script reads `benchmarks/experimental/07_range_drift_intent.json` by default. Other experimental fixtures can be passed explicitly:

```bash
python scripts/run_experimental_cause_band_eval.py benchmarks/experimental/10_range_persistent_without_critical.json
```

It is intentionally separate from the main `AuditEngine` and CI safety-eval runner.

Promotion path:

1. Keep the scenario here while semantics are unstable.
2. Add evaluator support behind an experimental flag.
3. Move fixtures into `benchmarks/fixtures/` only after the expected finding codes are implemented and stable.
