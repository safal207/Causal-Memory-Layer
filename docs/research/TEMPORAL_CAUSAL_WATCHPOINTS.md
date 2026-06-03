# Temporal Causal Watchpoints

## Status

This document is a future research direction note.

It does not define stable CML or vCML semantics yet. It does not claim prediction, enforcement, compliance, or production safety capability. It records a possible next layer above Cause Band and Causal Feedback Memory.

## Core idea

Some causal failures do not appear as completed mistakes immediately.

They begin as latent causes that may become real only when time and matching conditions align.

```text
Future mistake = latent cause + time + matching conditions
```

A Temporal Causal Watchpoint is a remembered causal hypothesis waiting for activation.

```text
Watchpoint = remembered cause waiting for activation
```

## Simple framing

Logs can show what happened.

CML can check whether the reason for an action was valid.

Cause Band can show whether that reason drifted over time.

Temporal Causal Watchpoints add another question:

```text
Is there a latent causal pattern that has not failed yet, but should be watched over time?
```

## Why this matters

A system may see an early warning sign that is not yet a failure.

For example:

```text
safe_range -> warning_range
```

This may not justify a hard failure. But if similar warning signs accumulate or later conditions match, the latent cause may activate.

A watchpoint lets the system preserve that unfinished causal pattern without pretending that failure has already happened.

## Relationship to Cause Band

Cause Band describes movement through admissibility bands:

```text
safe_range -> warning_range -> danger_range -> critical_range
```

Temporal Causal Watchpoints focus on the waiting state between early drift and actual failure:

```text
safe_range -> warning_range -> latent_watchpoint -> condition_match -> active_failure
```

Cause Band answers:

```text
How did the causal signal move over time?
```

Temporal Causal Watchpoints answer:

```text
Which latent causal patterns should be remembered and watched for future activation?
```

## Lifecycle

A watchpoint lifecycle may look like this:

```text
observed_signal
-> latent_cause_registered
-> watch_conditions_defined
-> time_passes
-> matching_conditions_observed
-> watchpoint_activated
-> alert_or_policy_review
-> lesson_recorded
```

A watchpoint is not a prediction. It is a conditional causal memory.

## Candidate watchpoint shape

```json
{
  "watchpoint_id": "wp_external_context_goal_shift_v1",
  "status": "latent",
  "source_trace_id": "agent-intent-drift-cause-band-example",
  "pattern": "external_context_becomes_goal_candidate",
  "signal": "authorization_context",
  "first_seen": {
    "record_id": "ai3",
    "band": "warning_range",
    "observed_state": "embedded_instruction_observed"
  },
  "activation_conditions": [
    "external_context_is_treated_as_goal",
    "downstream_action_is_prepared",
    "explicit_user_authorization_is_missing"
  ],
  "activation_window": {
    "unit": "steps",
    "value": 3
  },
  "on_activation": "raise_causal_alert",
  "lesson_candidate": "External context should not become a new goal without explicit authorization."
}
```

## Watchpoint states

Suggested states:

```text
latent       — remembered but not active
watching     — actively monitoring matching conditions
activated    — conditions matched
expired      — activation window closed
resolved     — reviewed and closed
promoted     — converted into stable policy or test
```

These states are not stable CML semantics yet. They are a candidate vocabulary for future work.

## Activation conditions

A watchpoint should define activation conditions explicitly.

Examples:

```text
same_signal_reappears
non_safe_band_repeats
external_context_becomes_goal
authorization_source_changes
human_confirmation_missing
downstream_action_prepared
critical_resource_targeted
```

A watchpoint should not activate merely because time passed. Time matters because it creates a window where conditions may align.

## Time semantics

Time can be represented in multiple ways:

```text
steps       — ordered trajectory events
turns       — dialogue turns
records     — CML records
seconds     — wall-clock time
sessions    — repeated interactions
revisions   — policy or workflow versions
```

Early work should prefer `steps` or `records` because they are deterministic and easier to test.

## Difference from prediction

A watchpoint does not say:

```text
This failure will happen.
```

It says:

```text
A latent causal pattern was observed. If these conditions appear within this time window, the pattern should be treated as activated.
```

This distinction matters. CML should avoid magical future claims and stay grounded in observable traces and explicit conditions.

## Difference from feedback memory

Causal Feedback Memory stores lessons from mistakes:

```text
mistake -> lesson -> policy candidate -> test -> review
```

Temporal Causal Watchpoints store unfinished mistake patterns:

```text
early signal -> latent cause -> watch conditions -> activation or expiry
```

Together:

```text
Causal Feedback Memory learns from completed mistakes.
Temporal Causal Watchpoints watch unfinished mistakes.
```

## Example: agent intent drift

In the agent intent drift example, the agent starts with a bounded request:

```text
summarize a document
```

Then the agent observes instruction-like context inside the document.

At that moment, a watchpoint could be registered:

```text
pattern = external_context_becomes_goal_candidate
status = latent
first_seen = warning_range
```

It would activate only if later conditions appear:

```text
external context is treated as goal
AND downstream action is prepared
AND explicit user authorization is missing
```

This lets CML distinguish:

```text
early warning sign != completed failure
```

while still preserving the causal pattern for future checking.

## Potential uses

Temporal Causal Watchpoints may be useful for:

- AI-agent tool-use oversight,
- prompt-injection-resilient workflows,
- enterprise agent governance,
- long-running automation,
- multi-session review trails,
- recurring authorization drift,
- staged security or compliance reviews.

## Non-goals

This concept does not claim:

- future prediction,
- autonomous policy rewriting,
- production-ready detection,
- enforcement or blocking,
- compliance certification,
- stable vCML semantics,
- active benchmark integration.

## Safety boundary

Watchpoints should not automatically rewrite policy.

A safe loop should look like this:

```text
watchpoint activated
-> evidence collected
-> lesson proposed
-> test proposed
-> human or review process approves
-> policy updated only after review
```

This keeps learning controlled and auditable.

## Research questions

1. Should watchpoints be stored as sidecar metadata, audit metadata, or a separate memory layer?
2. What is the minimal stable watchpoint schema?
3. Should activation windows be based on steps, records, turns, or wall-clock time?
4. Should activation produce a finding, a diagnostic, or a policy-review request?
5. How should watchpoints expire?
6. Can watchpoints become regression tests after repeated activation?
7. How should watchpoints interact with Cause Band recovery and oscillation diagnostics?

## Positioning statement

```text
Temporal Causal Watchpoints let CML remember unfinished causal failures and watch whether time and conditions activate them.
```

Shorter:

```text
Learn from unfinished mistakes.
```

## Relationship to current CML work

This future direction builds on:

- CML causal lineage checking,
- Cause Band range deviation over time,
- trajectory diagnostics,
- agent intent drift examples,
- future causal feedback memory.

It should remain experimental until concrete schemas, tests, and review semantics exist.
