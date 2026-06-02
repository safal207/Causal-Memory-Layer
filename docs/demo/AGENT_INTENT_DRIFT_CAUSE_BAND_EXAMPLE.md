# Agent Intent Drift Cause Band Example

## Purpose

This demo shows how Cause Band can describe intent or authorization-context drift inside a realistic AI-agent workflow.

The example is illustrative. It is not part of the active benchmark runner and does not change stable CML or vCML semantics.

## Example file

```text
examples/agent_intent_drift_trace.json
```

The file contains two layers:

```text
agent_trace          — illustrative agent action chain
cause_band_sidecar   — experimental trajectory interpretation
```

## Scenario

An agent receives a bounded user request:

```text
summarize this document
```

The agent then reads the document. While reading, it observes instruction-like text inside the document and gradually treats that context as possible operational guidance.

The final step is only a draft external action, not a completed action. The point is not enforcement. The point is trajectory visibility.

## Ordinary log view

A normal log might show:

```text
request_summary -> read_document -> extract_document_instruction -> consider_instruction_as_goal -> prepare_external_action_draft
```

This is useful, but it mostly says what happened.

## Cause Band view

The Cause Band sidecar asks whether the authorization context remained inside the admissible range over time.

Trajectory:

```text
safe_range -> safe_range -> warning_range -> danger_range -> critical_range
```

Interpretation:

```text
user-requested summary
-> document read remains inside request
-> embedded instruction-like content observed
-> embedded context treated as goal
-> unverified external action draft prepared
```

Expected findings:

```text
CML-AUDIT-RANGE-DRIFT
CML-AUDIT-RANGE-PERSISTENT_DEVIATION
CML-AUDIT-RANGE-CRITICAL_EXIT
```

Expected diagnostics:

```text
trajectory_direction = degrading
recovered_to_safe = false
oscillating = false
max_consecutive_outside_safe = 3
```

## Why this matters

The causal chain can appear structurally connected:

```text
ai1 -> ai2 -> ai3 -> ai4 -> ai5
```

But the authorization context changes meaning over time.

CML can therefore distinguish two questions:

```text
Is the chain connected?
Did the reason remain admissible?
```

This is the research value of Cause Band: a trace may remain structurally connected while drifting outside its admissible causal range.

## Relationship to prompt injection and agent safety

This example is intentionally neutral and non-operational. It does not provide attack instructions.

It models a common agent-safety shape:

```text
external context is observed -> context is over-trusted -> downstream action is prepared
```

The important point is not the content of the embedded text. The important point is the causal drift:

```text
requested task -> ambiguous context -> new goal candidate -> unverified action
```

## How to use this example

This file is not directly consumed by the current experimental evaluator because the evaluator expects a Cause Band fixture at the top level.

For now, the example is documentation-oriented: it shows how an agent trace and a Cause Band sidecar can live together.

A future adapter could extract:

```text
example.cause_band_sidecar
```

and pass it to:

```python
cml.experimental.cause_band.evaluate_fixture(...)
```

## Current boundary

This example does not claim:

- production prompt-injection detection,
- enforcement or blocking behavior,
- stable vCML schema support,
- compliance certification,
- active safety-eval benchmark coverage.

It demonstrates one idea:

```text
CML can audit not only broken causal links, but also intent drift inside valid-looking agent workflows.
```

## Next steps

Good follow-up work:

1. Add an adapter that evaluates `cause_band_sidecar` from example files.
2. Add a CLI option for sidecar extraction.
3. Add an example with recovery after drift.
4. Keep all examples experimental until schema and severity semantics are stable.
