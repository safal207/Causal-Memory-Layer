# Multi-hop QA Causal Mismatch (A→B vs A→C)

Input: `examples/multihop_qa_mismatch_log.jsonl`

## What the audit engine reports

Running the current `AuditEngine` (R1–R4, no custom rules) on this fixture:

```
summary: total=8, ok=8, warnings=0, failures=0, passed=True
findings: []
```

The audit passes. R1 skips `h2_B` because its `parent_cause` is `null`.
R2 skips it because `permitted_by = "unobserved_parent"` — the gap is
explicitly marked, which satisfies the gap-marking rule. R3 does not apply
(no SECRET / NET_OUT). There are no custom rules configured.

This is the interesting part of the example: **the current rule set does not
flag a causally-orphaned hop by itself.** The required B edge is marked as a
gap, which is formally allowed.

## What the causal chain reveals

The failure class is only visible through chain reconstruction:

```
ancestors("ans1") = {q1, h1, h2_C, h3, h4, h5, ans1}
ancestors("h2_B") = {"h2_B"}   # only self — no upstream causal lineage
```

(`ancestors()` in `cml/chain.py` returns the record itself plus its upstream
chain, so an isolated record's ancestor set is exactly `{self}`.)

The answer record `ans1` has a complete 5-hop chain back to `q1`, but the chain
goes through `h2_C`, not `h2_B`. The required intermediate fact (`h2_B`) was
recorded as a causal gap and then silently dropped from the path that produced
the answer. It appears in the log but is never referenced as a `parent_cause`
downstream.

## Why this matters

The textual reasoning trace (A → C → D → E → Z) is internally consistent and
passes R1/R2. The substitution of A→B with A→C is invisible to the default
audit rules and only surfaces when you compare the reconstructed ancestor set
of the answer against the ground-truth required path.

This example is a walkthrough of a failure class CML is designed to expose at
the chain-inspection level: a functionally valid answer produced through a
causally complete but incorrect path, with the required edge marked as a gap
rather than carried forward.

A custom rule or an external ground-truth check (e.g. asserting that every
required edge id appears in `ancestors(answer_id)`) is what would turn this
from a chain observation into an audit FAIL. See `examples/audit_config_example.yaml`
for the custom-rule mechanism.
