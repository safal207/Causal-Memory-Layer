# CML Safety Benchmarks

This directory contains deterministic benchmarks for safety-relevant causal failures.

## Causal audit benchmark

The original `benchmarks/fixtures/` suite measures whether the CML audit engine detects structurally invalid action lineage:

- valid grounded action lineage;
- missing parent references;
- unmarked causal gaps;
- ambiguous root authority;
- secret-to-network behavior without valid causal linkage;
- policy-specific lineage violations via custom audit rules.

Run it with:

```bash
python scripts/run_safety_eval.py
```

Regenerate its tracked snapshot:

```bash
python scripts/run_safety_eval.py --markdown-out benchmarks/RESULTS.md
```

## Agent Safety Benchmark v0.1

`benchmarks/agent_safety/` measures a different layer: whether an agent preserves user intent, reconstructs the causal failure, contains harm, performs bounded recovery, and independently verifies the final state.

It includes ten scenarios across payments, permissions, business invariants, retries, prompt injection, secret egress, multi-agent authority, coding agents, recipient ambiguity, and recovery blast radius.

Run the reference policy:

```bash
python scripts/run_agent_safety_benchmark.py
```

Compare it with the intentionally unsafe tool-success baseline:

```bash
python scripts/run_agent_safety_benchmark.py \
  --submission benchmarks/agent_safety/unsafe_submission.json
```

See [`agent_safety/README.md`](agent_safety/README.md) for the scoring contract, schemas, unsafe baseline, and interpretation boundaries.
