# Technical Report Outline

Status: draft outline for a reviewer-facing technical report.

Purpose: define the structure of a short technical report that can support a $50k–$100k grant application by making CML's research claim, benchmark method, evidence, and limitations explicit.

## Working title

```text
Causal Memory Layer: Causal Validity Checking for Agentic AI Action Traces
```

Alternative title:

```text
Operational Success Is Not Causal Legitimacy: A Deterministic Audit Layer for Agentic AI Workflows
```

## Abstract draft

Modern AI agents increasingly perform actions rather than only generate text. In high-stakes workflows, an action can succeed operationally while lacking valid authorization, approval, intent, or responsibility lineage. This creates a gap between ordinary logs, which record what happened, and auditability, which requires evidence for why an action was allowed.

Causal Memory Layer (CML) is an open-source causal audit layer for structured action traces. CML reconstructs causal chains and emits deterministic findings for selected classes of causally invalid behavior, including missing parent authorization, ambiguous root authority, unmarked causal gaps, and sensitive access followed by outbound behavior without valid lineage. This report describes the CML record model, audit rules, benchmark fixtures, current reproducibility results, limitations, and a roadmap for external validation.

## 1. Introduction

Key points:

- AI systems are moving from text generation to action execution.
- Output correctness is not enough for high-stakes workflows.
- Logs and traces often show what happened but not why it was allowed.
- CML introduces causal validity checking as a narrow oversight primitive.

Core invariant:

```text
A system may be functionally correct while being causally invalid.
```

## 2. Problem statement

Research question:

```text
How can we detect actions that appear operationally valid but are causally invalid because authorization, approval, intent, or responsibility lineage is missing, ambiguous, or broken?
```

Failure examples:

- missing parent cause;
- ambiguous root authority;
- unmarked causal gap;
- secret-to-network path without valid lineage;
- stale approval reused in a new context;
- delegated agent action without valid authority handoff.

## 3. CML model

Describe:

- CausalRecord fields;
- parent cause;
- permitted_by;
- actor/action/object;
- responsibility lineage;
- root event semantics;
- audit findings.

Example minimal record:

```json
{
  "id": "evt-001",
  "timestamp": 1690000001000000000,
  "actor": {"pid": 1000, "uid": 0},
  "action": "write",
  "object": "/data/funds.db",
  "permitted_by": "root_event:manager_approval",
  "parent_cause": null
}
```

## 4. Audit rules

Current finding families:

| Rule | Meaning |
| --- | --- |
| `CML-AUDIT-R1-MISSING_PARENT` | A parent cause is referenced but missing from the log. |
| `CML-AUDIT-R2-GAP_NOT_MARKED` | A causal gap exists but was not explicitly marked. |
| `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN` | Sensitive access and outbound behavior lack valid causal linkage. |
| `CML-AUDIT-R4-AMBIGUOUS_ROOT` | Root authority is malformed or ambiguous. |
| `CML-AUDIT-R5-*` | Policy-specific custom rule failure. |

## 5. Benchmark methodology

Describe:

- deterministic fixtures;
- expected findings;
- runner command;
- pass/fail matching;
- regression role;
- why benchmark is narrow and falsifiable.

Current command:

```bash
python scripts/run_safety_eval.py
```

Current benchmark assets:

- `benchmarks/fixtures/`
- `benchmarks/RESULTS.md`
- `docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md`

## 6. Current results

Current tracked result:

```text
Total cases: 6
Matched cases: 6
Mismatches: 0
Expected passed / failed: 3 / 3
Predicted passed / failed: 3 / 3
```

Interpretation:

```text
For the current curated fixtures, the implemented audit rules reproduce expected causal-validity findings.
```

Non-interpretation:

```text
This does not prove production safety, complete security coverage, or full AI alignment.
```

## 7. Demo walkthrough

Use Docker walkthrough as the concrete example:

- broken causal chain;
- missing parent finding;
- fixed causal chain;
- valid result;
- same action, different causal lineage.

Path:

```text
docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md
```

## 8. Relationship to adjacent layers

Explain boundaries:

| Layer | Question |
| --- | --- |
| Logs | What happened? |
| Tracing | Where and when did it happen? |
| LTP | Is the thread still continuous and admissible? |
| CML | Why was this action allowed? |
| CaPU | Should this transition proceed? |
| TTM DB | What is the immutable ground truth? |

## 9. External validation plan

Reference:

```text
docs/evidence/EXTERNAL_VALIDATION_PROTOCOL.md
```

Targets:

- 2 independent validation notes for a $50k grant;
- 3–5 validation notes for a stronger $100k case;
- clean environment reproduction;
- tests, benchmark, Docker demo;
- limitations and failures reported honestly.

## 10. Limitations

CML does not currently claim:

- full AI safety;
- runtime enforcement;
- production IAM integration;
- certified compliance;
- complete coverage of causal failures;
- replacement for observability, SIEM, EDR, or tracing systems.

CML is currently best understood as:

```text
A causal-validity audit primitive for structured action traces.
```

## 11. Roadmap

Near-term:

- expand benchmark fixtures to 30–50;
- define 10–12 failure classes;
- add machine-readable expected findings;
- generate Markdown and JSON benchmark reports;
- collect external validation notes;
- publish a short technical report.

## 12. Conclusion

CML contributes a narrow but testable safety primitive: distinguishing operational success from causal legitimacy. This is relevant for agentic AI systems because future oversight will require not only records of what agents did, but evidence of why actions were allowed and whether responsibility was preserved.

## Appendix A — Reproduction commands

```bash
pip install -e ".[dev]"
pytest
python scripts/run_safety_eval.py
docker compose up --build
```

## Appendix B — Evidence links

- `docs/GRANT_REVIEWER_CHECKLIST.md`
- `docs/GRANT_EVIDENCE.md`
- `docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md`
- `docs/evidence/BENCHMARK_EXPANSION_PLAN_50K_100K.md`
- `docs/evidence/EXTERNAL_VALIDATION_PROTOCOL.md`
- `docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md`
