# Cause Band Range Policy Semantics

## Status

This document is a proposed stable-semantics draft for Cause Band range policies.

It is not yet a normative vCML extension and does not promote Cause Band out of experimental status. Its purpose is to define the semantic contract that must be stabilized before Cause Band findings can move from experimental sidecar evaluation toward formal CML audit rules.

## Core principle

Cause Band treats cause as temporal range deviation:

```text
Cause = range deviation over time
```

More precisely:

```text
Cause(t) = Drift(State(t), ExpectedRange) x Duration x Direction
```

A range policy defines how a signal is classified over time and when movement across admissibility bands becomes a causal finding.

## Band hierarchy

A Cause Band policy uses a four-level hierarchy:

```text
safe_range < warning_range < danger_range < critical_range
```

The hierarchy is stable. The labels inside each band are policy-defined.

For example, the band names are stable:

```text
safe_range
warning_range
danger_range
critical_range
```

But the semantic labels assigned to each band are policy-specific:

```json
{
  "safe_range": "educational_or_abstract",
  "warning_range": "dual_use_or_procedural",
  "danger_range": "harmful_actionable_instruction",
  "critical_range": "bypass_or_abuse_enablement"
}
```

## Signal identity

A range policy MUST define the signal being evaluated.

Examples:

```text
user_intent
system_state
authorization_context
risk_level
data_sensitivity
execution_privilege
```

A signal is the dimension whose state moves through admissibility bands over time.

A policy SHOULD NOT mix unrelated signals inside one trajectory. For example, `user_intent` and `data_sensitivity` should usually be evaluated by separate policies unless a composite policy explicitly defines how they interact.

## Minimal policy shape

A minimal stable policy should look like this:

```json
{
  "range_policy": {
    "id": "intent_range_policy_v1",
    "signal": "user_intent",
    "bands": {
      "safe_range": "educational_or_abstract",
      "warning_range": "dual_use_or_procedural",
      "danger_range": "harmful_actionable_instruction",
      "critical_range": "bypass_or_abuse_enablement"
    },
    "duration_threshold": {
      "unit": "steps",
      "value": 3
    },
    "direction_policy": "degrading_requires_escalation",
    "recovery_policy": "requires_safe_range_reentry",
    "severity_mapping": {
      "CML-AUDIT-RANGE-DRIFT": "WARN",
      "CML-AUDIT-RANGE-PERSISTENT_DEVIATION": "FAIL",
      "CML-AUDIT-RANGE-CRITICAL_EXIT": "FAIL"
    }
  }
}
```

## Trajectory event shape

A trajectory event should minimally identify:

```json
{
  "step": 3,
  "record_id": "rd3",
  "signal": "user_intent",
  "observed_state": "procedural_detail_request",
  "band": "danger_range"
}
```

Required fields:

- `step` or equivalent ordering key,
- `signal`,
- `observed_state`,
- `band`.

Recommended fields:

- `record_id`, when the trajectory event maps to a CML record,
- `timestamp`, when wall-clock duration matters,
- `confidence`, when classification is probabilistic,
- `note`, when human review needs context.

## Duration semantics

A duration threshold MUST define its unit explicitly.

Supported candidate units:

```text
steps       — count ordered trajectory events
records     — count CML records
seconds     — wall-clock time
turns       — dialogue turns
operations  — system actions
```

For early Cause Band semantics, `steps` is the recommended default because it works for both conversation and system traces without requiring timestamp normalization.

Example:

```json
{
  "duration_threshold": {
    "unit": "steps",
    "value": 3
  }
}
```

This means that three consecutive non-safe trajectory events may trigger persistent deviation if recovery is not observed.

## Direction semantics

Direction describes how the signal moves across the band hierarchy.

Possible direction states:

```text
stable       — remains in the same band
recovering   — moves toward safer bands
degrading    — moves toward more dangerous bands
oscillating  — repeatedly crosses bands without stable recovery
unknown      — insufficient ordering or classification data
```

A degrading trajectory should increase audit concern.

Example:

```text
safe_range -> warning_range -> danger_range -> critical_range
```

This is degrading.

Example:

```text
danger_range -> warning_range -> safe_range
```

This is recovering.

## Recovery semantics

A recovery policy defines when a trace is considered to have returned to admissibility.

Candidate recovery policies:

```text
requires_safe_range_reentry
requires_n_safe_steps
requires_human_review
no_automatic_recovery
```

Recommended initial policy:

```text
requires_safe_range_reentry
```

For stricter systems, use:

```text
requires_n_safe_steps
```

Example:

```json
{
  "recovery_policy": {
    "type": "requires_n_safe_steps",
    "value": 2
  }
}
```

## Proposed finding semantics

### CML-AUDIT-RANGE-DRIFT

Trigger when the signal leaves `safe_range`.

Recommended default severity:

```text
WARN
```

Interpretation:

The trace is no longer fully inside the admissible band, but the deviation may be transient.

### CML-AUDIT-RANGE-PERSISTENT_DEVIATION

Trigger when the signal remains outside `safe_range` for at least the configured duration threshold without recovery.

Recommended default severity:

```text
FAIL
```

Interpretation:

The causal signal is no longer a single anomaly. It is sustained deviation over time.

### CML-AUDIT-RANGE-CRITICAL_EXIT

Trigger when the signal reaches `critical_range`.

Recommended default severity:

```text
FAIL
```

Interpretation:

The trajectory has exited the admissible range. The trace may remain structurally valid, but its causal admissibility has failed.

## Finding attachment semantics

Cause Band findings should attach to the most specific available target.

Preferred order:

1. `record_id` if a trajectory step maps to a CML record,
2. `trajectory_id` if the finding spans multiple records or steps,
3. `range_policy.id` if the finding is policy-level only,
4. synthetic experimental id only as a fallback.

For multi-step findings, the finding should preserve the relevant path using `chain_ids` or a future metadata field.

Current `Finding` supports:

```text
record_id
chain_ids
```

Future versions may need explicit metadata such as:

```json
{
  "metadata": {
    "signal": "user_intent",
    "bands": ["safe_range", "warning_range", "danger_range"],
    "range_policy_id": "intent_range_policy_v1"
  }
}
```

This should not be added until the audit result schema is intentionally versioned.

## Sidecar vs vCML extension

Current Cause Band evaluation uses sidecar policy and sidecar trajectory metadata.

This should remain the default experimental path.

A vCML extension should only be considered if:

- multiple fixtures prove the range policy shape is stable,
- record-to-trajectory attachment semantics are clear,
- duration and recovery rules are stable,
- audit output schema changes are versioned,
- default `AuditEngine` behavior remains unchanged unless explicitly opted in.

## Promotion criteria

Cause Band can be considered for promotion beyond experimental status only when:

- range policy schema is stable,
- at least three distinct experimental fixtures exist,
- tests cover drift, persistence, critical exit, and recovery,
- severity mapping is documented,
- finding attachment semantics are documented,
- non-claims remain explicit,
- default audit behavior remains backward compatible,
- active benchmark changes are intentional and documented.

## Non-goals

This document does not:

- make Cause Band part of stable vCML semantics,
- remove the experimental flag,
- define production enforcement behavior,
- claim jailbreak detection,
- claim compliance or certification coverage,
- require active safety-eval benchmark changes.

## Open questions

1. Should `warning_range` always be a warning, or can some policies treat it as informational?
2. Should `critical_range` always fail, or can certain domains require human review instead?
3. Should confidence be required for LLM intent classification use cases?
4. Should recovery clear earlier findings or only add a new recovery finding?
5. Should Cause Band use a dedicated audit result metadata field in v1?

## Relationship to current experimental implementation

The current experimental implementation provides:

- sidecar fixture evaluation,
- `CML-AUDIT-RANGE-*` findings,
- opt-in `AuditConfig` flag,
- tests for disabled and enabled behavior,
- documentation that keeps Cause Band non-normative.

This document defines the next semantic target before further implementation work.
