# Experimental Cause Band Audit Flag

## Status

This document describes an experimental, opt-in Cause Band integration path.

It is non-normative and does not change stable vCML semantics, default audit behavior, or active safety-eval benchmark expectations.

## Purpose

Cause Band models cause as temporal range deviation:

```text
Cause = range deviation over time
```

The experimental audit flag allows CML to evaluate a sidecar Cause Band fixture and emit future-facing range findings without making Cause Band part of the default `AuditEngine` behavior.

## Python usage

```python
from cml import AuditConfig, AuditEngine

config = AuditConfig(
    enable_experimental_cause_band=True,
    experimental_cause_band_fixture="benchmarks/experimental/07_range_drift_intent.json",
)

result = AuditEngine(config).run(records)
```

When enabled with a sidecar fixture, the engine may emit experimental findings such as:

```text
CML-AUDIT-RANGE-DRIFT
CML-AUDIT-RANGE-PERSISTENT_DEVIATION
CML-AUDIT-RANGE-CRITICAL_EXIT
```

## YAML usage

```yaml
experimental:
  enable_cause_band: true
  cause_band_fixture: benchmarks/experimental/07_range_drift_intent.json
```

Then load the config using the existing YAML path:

```python
from cml import AuditConfig, AuditEngine

config = AuditConfig.from_yaml("audit-config.yaml")
result = AuditEngine(config).run(records)
```

## Default behavior

By default, Cause Band evaluation is disabled:

```python
AuditConfig().enable_experimental_cause_band == False
```

No Cause Band findings are emitted unless both conditions are true:

1. `enable_experimental_cause_band=True`
2. `experimental_cause_band_fixture` points to a Cause Band sidecar fixture

This keeps current `AuditEngine` behavior and active benchmark behavior unchanged.

## Current sidecar model

The first integration uses a sidecar fixture rather than changing the `CausalRecord` or vCML schema.

This is intentional. Cause Band semantics are still experimental, so range metadata should remain outside the stable record format until the model is mature.

Current experimental fixture:

```text
benchmarks/experimental/07_range_drift_intent.json
```

## What this does

The experimental flag allows CML to evaluate a trajectory such as:

```text
safe_range -> warning_range -> danger_range -> critical_range
```

and report future-facing range findings.

This is useful for testing traces where a causal chain may remain structurally valid while its trajectory leaves the admissible range over time.

## What this does not do

This flag does not:

- make Cause Band part of stable vCML semantics,
- move experimental fixtures into active benchmark fixtures,
- change default audit output,
- provide production jailbreak detection,
- provide enforcement or blocking behavior,
- make compliance, safety, or certification claims.

## Relationship to existing audit rules

Existing CML audit rules check causal lineage integrity, such as missing parent causes, ambiguous roots, unmarked gaps, and broken responsibility chains.

Cause Band adds a temporal lens:

```text
Did the trace remain inside its admissible causal range over time?
```

This is complementary to reference-integrity rules. A chain can be structurally intact and still drift outside its admissible range.

## Recommended next steps

Before promoting Cause Band beyond experimental status:

1. Add more experimental fixtures for different drift patterns.
2. Define stable range-policy semantics.
3. Decide whether range metadata belongs in sidecar policy, vCML extensions, or external policy configuration.
4. Keep stable audit behavior unchanged until semantics are versioned.
5. Document all findings as experimental until promoted into formal audit-rule docs.

See the proposed semantics draft:

```text
docs/research/CAUSE_BAND_RANGE_POLICY_SEMANTICS.md
```

## Related artifacts

- `docs/research/CAUSE_BAND.md`
- `docs/research/CAUSE_BAND_AUDIT_RULE_SKETCH.md`
- `docs/research/CAUSE_BAND_RANGE_POLICY_SEMANTICS.md`
- `benchmarks/experimental/07_range_drift_intent.json`
- `cml/experimental/cause_band.py`
- `scripts/run_experimental_cause_band_eval.py`
- Issue `#102`
- Issue `#105`
