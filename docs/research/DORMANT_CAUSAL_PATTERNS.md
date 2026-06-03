# Dormant Causal Patterns

## Status

This document is a short framing note for Temporal Causal Watchpoints.

It is not a stable CML or vCML specification. It records a simple research vocabulary for causes that are present as patterns but not yet operationally active.

## Core idea

A cause may be present before it becomes active.

It can remain dormant until time and activation conditions make it operationally relevant.

```text
Dormant causal pattern = observed pattern + inactive status + activation conditions
```

Related Temporal Causal Watchpoint formula:

```text
Future mistake = latent cause + time + matching conditions
```

## Why this matters

Some failures are not born at the moment they become visible.

They may begin earlier as a weak signal, an incomplete pattern, or a context shift that is not yet enough to trigger a finding.

A dormant causal pattern lets CML represent:

```text
not safe enough to ignore
not active enough to fail
important enough to remember
```

## Plain-language example

A child builds a tower.

The tower has not fallen yet. But one block is tilted.

The tilted block is not the collapse. It is a dormant causal pattern.

If more blocks are placed on top, and the tilt increases, the dormant pattern may activate into a real failure.

In CML terms:

```text
tilted block -> watchpoint registered
more weight -> activation condition
collapse risk -> active causal concern
```

## Agent example

An agent is asked to summarize a document.

At first, the task is safe and bounded.

Then the agent observes instruction-like text inside the document.

That observation alone may not be a completed failure. But it can become a dormant causal pattern:

```text
external context may become a goal candidate
```

If later the agent treats that context as a goal and prepares an external action without explicit user authorization, the pattern activates.

```text
observed context -> dormant pattern -> goal shift -> unverified action
```

## Relationship to watchpoints

Temporal Causal Watchpoints are the operational memory form.

Dormant Causal Patterns are the conceptual form.

```text
Dormant Causal Pattern = what is remembered
Temporal Causal Watchpoint = how it is watched over time
```

## Difference from prediction

This is not a claim that CML knows the future.

A dormant pattern does not say:

```text
This failure will happen.
```

It says:

```text
This causal shape has appeared. If activation conditions later match, treat it as relevant.
```

The difference matters because CML should remain grounded in observable traces, explicit conditions, and auditable review.

## Candidate fields

A dormant causal pattern may need fields such as:

```json
{
  "pattern_id": "dcp_external_context_goal_shift_v1",
  "status": "dormant",
  "signal": "authorization_context",
  "observed_shape": "external_context_may_become_goal_candidate",
  "first_seen_record_id": "ai3",
  "activation_conditions": [
    "external_context_treated_as_goal",
    "downstream_action_prepared",
    "explicit_user_authorization_missing"
  ],
  "watchpoint_candidate": true
}
```

## Useful vocabulary

```text
dormant      — present but inactive
latent       — hidden or not yet operationally expressed
activation   — transition from watched pattern to active concern
condition    — observable requirement for activation
expiry       — the pattern did not activate within its window
promotion    — repeated pattern becomes policy or test candidate
```

## Non-goals

This note does not claim:

- future prediction,
- mystical or hidden knowledge,
- autonomous policy rewriting,
- production-ready enforcement,
- compliance certification,
- stable CML/vCML semantics.

## Positioning statement

```text
Dormant Causal Patterns give CML a way to remember causes whose time has not come yet, without pretending that failure has already happened.
```

Shorter:

```text
Some causes wait for conditions.
```
