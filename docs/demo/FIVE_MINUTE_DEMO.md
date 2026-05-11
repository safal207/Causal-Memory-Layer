# Five-minute CML demo

This walkthrough gives new users a quick "I get it" moment for CML:

> A system can be functionally correct while being causally invalid.

The demo uses the deterministic benchmark fixtures that already ship with the
repository. It does not make broad safety or compliance claims; it only shows
how CML reports selected causal-lineage failures.

## 1. Install locally

From the repository root:

```bash
pip install -e ".[dev]"
```

Optional sanity check:

```bash
pytest
```

## 2. Run the safety evaluation

```bash
python scripts/run_safety_eval.py
```

This runs the benchmark fixtures documented in
[`benchmarks/README.md`](../../benchmarks/README.md).

To regenerate the tracked Markdown report:

```bash
python scripts/run_safety_eval.py --markdown-out benchmarks/RESULTS.md
```

## 3. Read the expected finding

Open the benchmark evidence snapshot:

```bash
cat docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md
```

The snapshot lists the current fixture set and expected audit behavior. One
important failure class is:

```text
Secret-to-network without valid lineage
```

Expected behavior:

```text
CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN
```

## 4. Why this finding matters

In ordinary logs, a workflow might look successful:

1. A secret was read.
2. A network action happened.
3. The process completed.

CML asks a different question: was the network action causally grounded in a
valid chain of permission, intent, and responsibility?

If the chain is missing, the action may be operationally successful but
causally invalid. That is the kind of gap CML is designed to make visible.

## 5. Where to go next

- Benchmark overview: [`benchmarks/README.md`](../../benchmarks/README.md)
- Evidence snapshot: [`docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md`](../evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md)
- Getting started: [`docs/START_HERE.md`](../START_HERE.md)
- Wiki demo notes: [`docs/wiki/Demo.md`](../wiki/Demo.md)
