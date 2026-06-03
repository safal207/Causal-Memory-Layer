# CML Research Map

## Purpose

This document maps the current CML research surface so reviewers can understand the project without reading every note in isolation.

It is a navigation document, not a new theory. It organizes existing concepts, artifacts, experimental paths, and future directions.

## One-line thesis

```text
Logs show what happened. CML checks why it was allowed.
```

The extended research line adds:

```text
Cause Band checks whether the reason stayed admissible over time.
Temporal Watchpoints remember unfinished causal failures.
Dormant Patterns describe causes waiting for activation conditions.
```

## Layer map

```text
CML core
  -> causal validity checking for structured traces

Cause Band
  -> range deviation over time

Trajectory diagnostics
  -> degrading / recovering / oscillating / persistent deviation

Agent intent drift example
  -> realistic agent workflow with runnable Cause Band sidecar

Temporal Causal Watchpoints
  -> latent causal patterns watched over time

Dormant Causal Patterns
  -> causes that are present as inactive patterns and wait for conditions
```

## Reading order

### 1. Start with CML core

Read:

```text
docs/START_HERE.md
docs/REVIEWER_PATH.md
docs/NON_CLAIMS.md
```

Question answered:

```text
What is CML, what does it claim, and what does it not claim?
```

Core distinction:

```text
functionally correct != causally valid
```

### 2. Review benchmark evidence

Read:

```text
docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md
docs/evidence/EXTERNAL_VALIDATION_PROTOCOL.md
```

Question answered:

```text
What currently runs, and how can it be reviewed externally?
```

Boundary:

```text
Current deterministic benchmark evidence is separate from experimental Cause Band work.
```

### 3. Understand Cause Band

Read:

```text
docs/research/CAUSE_BAND.md
benchmarks/experimental/README.md
docs/demo/CAUSE_BAND_TRAJECTORY_WALKTHROUGH.md
```

Question answered:

```text
How can a cause be represented as a range deviation over time?
```

Core formula:

```text
Cause = range deviation over time
```

Band shape:

```text
safe_range -> warning_range -> danger_range -> critical_range
```

### 4. Review trajectory diagnostics

Read:

```text
cml/experimental/cause_band.py
cml/experimental/cause_band_trajectory.py
tests/test_experimental_cause_band_eval.py
```

Question answered:

```text
Can the experimental evaluator distinguish the shape of causal movement?
```

Current diagnostics:

```text
trajectory_direction
recovered_to_safe
oscillating
max_consecutive_outside_safe
```

Current finding codes remain limited to:

```text
CML-AUDIT-RANGE-DRIFT
CML-AUDIT-RANGE-PERSISTENT_DEVIATION
CML-AUDIT-RANGE-CRITICAL_EXIT
```

Recovery and oscillation are diagnostics only for now.

### 5. Run the agent intent drift example

Read:

```text
docs/demo/AGENT_INTENT_DRIFT_CAUSE_BAND_EXAMPLE.md
examples/agent_intent_drift_trace.json
```

Run:

```bash
python scripts/run_experimental_cause_band_eval.py examples/agent_intent_drift_trace.json
```

Machine-readable output:

```bash
python scripts/run_experimental_cause_band_eval.py examples/agent_intent_drift_trace.json --json
```

Question answered:

```text
Can Cause Band be attached to a realistic AI-agent workflow?
```

Key distinction:

```text
Is the chain connected?
Did the reason remain admissible?
```

### 6. Understand Temporal Causal Watchpoints

Read:

```text
docs/research/TEMPORAL_CAUSAL_WATCHPOINTS.md
```

Question answered:

```text
How can CML remember unfinished causal failures over time?
```

Core formula:

```text
Future mistake = latent cause + time + matching conditions
```

Watchpoint formula:

```text
Watchpoint = remembered cause waiting for activation
```

Boundary:

```text
A watchpoint is not a prediction. It is a conditional causal memory.
```

### 7. Understand Dormant Causal Patterns

Read:

```text
docs/research/DORMANT_CAUSAL_PATTERNS.md
```

Question answered:

```text
What is the conceptual form behind a watchpoint?
```

Core formula:

```text
Dormant causal pattern = observed pattern + inactive status + activation conditions
```

Short framing:

```text
Some causes wait for conditions.
```

## Concept map

| Concept | Question answered | Status |
| :--- | :--- | :--- |
| CML core | Why was this action allowed? | Implemented core artifact |
| Benchmark fixtures | Can current audit findings be reproduced? | Active deterministic evidence |
| Cause Band | Did the cause remain admissible over time? | Experimental research |
| Trajectory diagnostics | What shape did the drift take? | Experimental evaluator support |
| Agent intent drift example | How does this look in an agent workflow? | Runnable experimental demo |
| Temporal Causal Watchpoints | Which unfinished causal patterns should be watched? | Future research direction |
| Dormant Causal Patterns | What is a cause that exists but is not active yet? | Research framing |
| Quantum causal audit | How might CML help future quantum-assisted AI audit? | Future research direction |

## Current artifact chain

```text
concept
-> docs
-> experimental fixtures
-> evaluator
-> diagnostics
-> tests
-> AuditEngine opt-in flag
-> trajectory walkthrough
-> runnable agent sidecar demo
-> future watchpoint framing
```

This chain matters because the project is not only naming ideas. It is turning selected ideas into reviewable artifacts.

## What is stable today

Stable or core-facing work:

```text
CML causal lineage checking
basic audit engine behavior
benchmark runner for active fixtures
reviewer-facing non-claims
external validation protocol
```

These are the safer areas to emphasize in first-pass review.

## What is experimental today

Experimental work:

```text
Cause Band semantics
range-policy fixtures
trajectory diagnostics
experimental AuditEngine Cause Band flag
agent intent drift sidecar evaluation
```

These should be presented as experimental and research-facing.

## What is future-facing today

Future-facing work:

```text
Temporal Causal Watchpoints
Dormant Causal Patterns
Causal Feedback Memory
Quantum-safe / quantum-assisted causal audit
```

These should not be presented as production features.

## Claim boundaries

Do not claim that CML currently provides:

- production jailbreak detection,
- full AI safety solution,
- autonomous policy rewriting,
- future prediction,
- compliance certification,
- stable Cause Band/vCML semantics,
- quantum security guarantees,
- enforcement or blocking behavior by default.

Preferred claim:

```text
CML is a causal audit layer for structured action traces, with experimental research on temporal causal admissibility through Cause Band.
```

## Strong positioning statements

General CML:

```text
Logs show what happened. CML checks why it was allowed.
```

Cause Band:

```text
Cause Band models cause as range deviation over time.
```

Agent safety:

```text
CML can audit not only broken causal links, but also intent drift inside valid-looking agent workflows.
```

Watchpoints:

```text
Temporal Causal Watchpoints let CML remember unfinished causal failures and watch whether time and conditions activate them.
```

Dormant patterns:

```text
Some causes wait for conditions.
```

## Near-term next steps

Recommended next steps are implementation and consolidation, not more terminology.

1. Add a minimal watchpoint schema draft.
2. Add one watchpoint example derived from `examples/agent_intent_drift_trace.json`.
3. Add a small evaluator for watchpoint activation over ordered records or steps.
4. Decide whether activation creates a finding, diagnostic, or policy-review request.
5. Keep all watchpoint work experimental until tested.

## Reviewer path

A reviewer who has 10 minutes should read:

```text
README.md
docs/NON_CLAIMS.md
docs/research/CML_RESEARCH_MAP.md
docs/demo/AGENT_INTENT_DRIFT_CAUSE_BAND_EXAMPLE.md
```

A reviewer who has 30 minutes should additionally read:

```text
docs/research/CAUSE_BAND.md
docs/demo/CAUSE_BAND_TRAJECTORY_WALKTHROUGH.md
docs/research/TEMPORAL_CAUSAL_WATCHPOINTS.md
docs/research/DORMANT_CAUSAL_PATTERNS.md
```

A technical reviewer should also inspect:

```text
cml/experimental/cause_band.py
cml/experimental/cause_band_trajectory.py
scripts/run_experimental_cause_band_eval.py
tests/test_experimental_cause_band_eval.py
```

## Bottom line

CML starts with a narrow audit primitive:

```text
Was this action causally valid?
```

The research extension asks a temporal version:

```text
Did the reason stay valid over time?
```

The watchpoint extension asks a future-facing but non-predictive question:

```text
Which unfinished causal patterns should be remembered and watched for activation?
```

This map should help keep those layers clear.
