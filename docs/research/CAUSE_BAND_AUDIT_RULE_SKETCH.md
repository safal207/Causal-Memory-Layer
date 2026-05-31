# Cause Band Audit Rule Sketch

## Status

This document is a non-normative rule sketch.

It describes how the Cause Band research concept could become deterministic CML audit behavior in future versions. It does not change the current vCML record format, CLI behavior, API behavior, benchmark expectations, or existing audit findings.

## Background

Cause Band defines cause as temporal range deviation:

```text
Cause = range deviation over time
```

More precisely:

```text
Cause(t) = Drift(State(t), ExpectedRange) x Duration x Direction
```

The audit question is:

```text
Did the trace remain inside its admissible causal range over time?
```

Current CML rules focus on explicit causal lineage integrity: missing parent causes, ambiguous roots, unmarked gaps, and broken responsibility chains. Cause Band adds a temporal lens for drift, persistence, and direction.

## Proposed finding family

The following finding codes are placeholders until formalized in a versioned audit-rule specification.

```text
CML-AUDIT-RANGE-DRIFT
CML-AUDIT-RANGE-PERSISTENT_DEVIATION
CML-AUDIT-RANGE-CRITICAL_EXIT
```

## Rule sketch: RANGE-DRIFT

### Intent

Detect when an observed signal moves from an admissible range into a warning or danger range.

### Candidate trigger

```text
observed_state(t) outside expected_range
AND drift_magnitude >= configured_threshold
```

### Example

```json
{
  "signal": "user_intent",
  "expected_range": "educational_or_abstract",
  "observed_state": "dual_use_or_procedural",
  "finding": "CML-AUDIT-RANGE-DRIFT",
  "severity": "WARN"
}
```

### Interpretation

The trace has not necessarily become invalid yet, but it has crossed from normal causal admissibility into a monitored band.

## Rule sketch: RANGE-PERSISTENT_DEVIATION

### Intent

Detect when a drift is not transient and remains outside the admissible range for long enough to become causally meaningful.

### Candidate trigger

```text
observed_state(t..t+n) outside expected_range
AND duration >= configured_duration_threshold
AND recovery_signal not observed
```

### Example

```json
{
  "signal": "temperature",
  "expected_range": "36.3..37.2",
  "observed_values": ["38.4", "39.1", "39.0"],
  "duration": "6h",
  "finding": "CML-AUDIT-RANGE-PERSISTENT_DEVIATION",
  "severity": "FAIL"
}
```

### Interpretation

The cause is no longer a single anomalous value. The cause is sustained deviation over time.

## Rule sketch: RANGE-CRITICAL_EXIT

### Intent

Detect when the trace exits the admissible range into a critical band where continuation should be blocked, rejected, or escalated.

### Candidate trigger

```text
observed_state in critical_range
OR trajectory_direction == degrading
AND action_requested requires high-trust execution
```

### Example

```json
{
  "signal": "user_intent",
  "trajectory": [
    "fictional_textbook_framing",
    "continue_fragment",
    "add_procedural_detail",
    "remove_safety_language"
  ],
  "critical_range": "harmful_actionable_instruction",
  "finding": "CML-AUDIT-RANGE-CRITICAL_EXIT",
  "severity": "FAIL"
}
```

### Interpretation

The causal trajectory has exited the admissible band. The action may look locally coherent, but the trace no longer has valid causal admissibility.

## Minimal data model sketch

A future CML record or sidecar policy may need to represent:

```json
{
  "range_policy": {
    "signal": "user_intent",
    "safe_range": "educational_or_abstract",
    "warning_range": "dual_use_or_procedural",
    "danger_range": "harmful_actionable_instruction",
    "critical_range": "bypass_or_abuse_enablement",
    "duration_threshold": "3_steps",
    "direction_policy": "degrading_requires_escalation"
  }
}
```

This should remain separate from core vCML until the semantics are stable.

## Relationship to existing CML findings

Cause Band findings should complement, not replace, current lineage findings.

A trace can be invalid because:

- the parent cause is missing,
- the root authority is ambiguous,
- a causal gap was not marked,
- a secret-to-network chain is broken,
- or the trace has drifted outside its admissible range over time.

The last case is the Cause Band extension.

## Non-goals

This sketch does not define:

- final severity mappings,
- exact threshold defaults,
- full vCML schema changes,
- production enforcement behavior,
- model-safety guarantees,
- compliance or certification claims.

## Implementation path

A minimal future implementation could proceed in four stages:

1. Add example fixtures that encode range transitions over time.
2. Add deterministic evaluator helpers for drift, duration, and direction.
3. Add non-breaking audit findings under an experimental flag.
4. Promote stable semantics into versioned audit-rule documentation.

## Principle

```text
A causal chain can be structurally intact and still become invalid if its trajectory leaves the admissible band.
```

This is the bridge from causal lineage to temporal causal admissibility.
