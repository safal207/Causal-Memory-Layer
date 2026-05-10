# ⏱️ CML: The 5-Minute "Aha!" Moment

Welcome to the Causal Memory Layer (CML). This quick walkthrough demonstrates the core concept of CML: **A system can be functionally correct while being causally invalid.**

## 1. Local Setup
Let's install CML and its development dependencies locally so you can run the audit engine.

```bash
# Clone the repository if you haven't already
git clone [https://github.com/marcotannoia/Causal-Memory-Layer.git](https://github.com/marcotannoia/Causal-Memory-Layer.git)
cd Causal-Memory-Layer

# Install in editable mode
pip install -e ".[dev]"
```

## 2. Run the Evaluation
We'll run the existing safety evaluation script. This script simulates system behaviors and generates an audit report.

```bash
python scripts/run_safety_eval.py --markdown-out benchmarks/RESULTS.md
```
*(You can also run the full test suite with `pytest` if you want to verify the core engine).*

## 3. The Audit Result & Expected Finding
When you inspect the output (or the generated `RESULTS.md`), you will see a structured finding that looks like this:

```json
{
  "code": "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN",
  "severity": "critical",
  "message": "Network egress follows secret access without valid causal linkage."
}
```

## 4. Why This Matters (The Core Idea)
Imagine a script that reads a database password (Secret Access) and then makes an HTTP request to an external server (Network Egress). 

To a standard monitoring tool or a traditional logger, both actions succeeded without errors. The system is **functionally correct**. 

However, CML analyzes the *causal chain*. If the network request cannot cryptographically prove that it is part of an authorized chain stemming from a valid root event, CML flags it. It means data might be leaking outside of the allowed session. The execution is **causally invalid**.

## 📚 Learn More
To dive deeper into how we test this and see verified results, check out:
- [Benchmarks README](../../benchmarks/README.md)
- [Benchmark Evidence Snapshot](../evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md)

---
> **Note:** CML is an investigative tool for causal lineage and AI governance. It does not natively guarantee full regulatory compliance or replace a complete security architecture.
