# CML Benchmark Evidence Snapshot

**Purpose:** provide a compact reviewer-friendly summary of the deterministic CML safety-eval benchmark.

This document is intended for contributors, reviewers, grant evaluators, and pilot partners who need to understand what the benchmark covers, how to reproduce it, and what it does not prove.

## Summary

CML includes a small deterministic benchmark for causal audit failures. The benchmark checks whether the current CML audit engine produces expected findings on known causal-lineage scenarios.

Current tracked result:

- Total cases: **6**
- Matched cases: **6**
- Mismatches: **0**
- Expected passed / failed: **3 / 3**
- Predicted passed / failed: **3 / 3**

Source files:

- Benchmark overview: `benchmarks/README.md`
- Tracked results: `benchmarks/RESULTS.md`
- Fixtures: `benchmarks/fixtures/`
- Runner: `scripts/run_safety_eval.py`

## Reproduction command

Run the benchmark locally:

```bash
python scripts/run_safety_eval.py
```

Regenerate the tracked Markdown snapshot:

```bash
python scripts/run_safety_eval.py --markdown-out benchmarks/RESULTS.md
```

## What the benchmark tests

The benchmark verifies deterministic CML audit behavior against curated fixtures.

It currently covers:

| Failure class / case | Expected audit behavior |
|---|---|
| Valid grounded secret-to-network lineage | Should pass without findings. |
| Missing parent reference | Should fail with `CML-AUDIT-R1-MISSING_PARENT`. |
| Unmarked causal gap | Should produce `CML-AUDIT-R2-GAP_NOT_MARKED`. |
| Ambiguous root authority | Should produce `CML-AUDIT-R4-AMBIGUOUS_ROOT`. |
| Secret-to-network without valid lineage | Should fail with `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN`. |
| Custom rule: network action outside session ancestry | Should fail with `CML-AUDIT-R5-NET-OUTSIDE-SESSION`. |

## Why this matters

The benchmark demonstrates one important claim:

> CML can detect selected causally invalid action chains using deterministic fixtures and explicit expected audit findings.

This is different from ordinary logging. Logs may show that an action happened. CML checks whether the recorded action preserved valid causal lineage through parent causes, authority, responsibility, and policy-specific rule expectations.

## Reviewer interpretation

A reviewer can use this benchmark to check:

- whether the audit engine reproduces expected findings,
- whether regression changes preserve known causal semantics,
- whether fixture outputs match documented rule codes,
- whether new failure classes are added with explicit expected behavior.

## What this benchmark does not prove

This benchmark does **not** prove:

- complete AI safety,
- full security coverage,
- regulatory compliance,
- production readiness,
- protection against all causal attacks,
- correctness of all possible authorization models,
- suitability for every deployment environment.

It is a focused regression/evidence artifact for current CML causal audit rules.

## How to extend the benchmark

A good benchmark contribution should include:

1. A minimal fixture in `benchmarks/fixtures/`.
2. A clear expected pass/fail result.
3. Expected audit rule codes.
4. A short explanation of the causal-lineage failure.
5. Updated `benchmarks/RESULTS.md` generated from the runner.

Good candidate future fixtures:

- delegated authority chain,
- responsibility handoff across agents,
- multi-tenant domain crossing,
- malformed CTAG seal,
- secret read followed by delayed network egress,
- valid exception path with explicit approval.

## Evidence quality principle

CML evidence should remain narrow, reproducible, and falsifiable.

A strong benchmark result should say:

> For these fixtures, these rules produce these findings.

It should not claim broader safety or compliance without additional evidence.
