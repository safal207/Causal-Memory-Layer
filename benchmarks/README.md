# CML Safety-Eval Benchmark

This directory contains a small deterministic benchmark for safety-relevant causal audit failures.

The benchmark is designed to show that CML can detect causally invalid action chains, not just malformed logs in the abstract.

## What it covers

Current fixtures exercise:

- valid grounded action lineage
- missing parent references
- unmarked causal gaps
- ambiguous root authority
- secret-to-network behavior without valid causal linkage
- policy-specific lineage violations via custom audit rules

## Why this matters

For agentic oversight, an action can look acceptable at the surface level while still being causally invalid.

This benchmark makes that measurable with deterministic fixtures and explicit expected audit findings.

## Run locally

```bash
python scripts/run_safety_eval.py
```

To regenerate the tracked Markdown snapshot:

```bash
python scripts/run_safety_eval.py --markdown-out benchmarks/RESULTS.md
```
