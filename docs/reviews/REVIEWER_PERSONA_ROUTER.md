# Reviewer Persona Router v0.1

## Purpose

The Reviewer Persona Router keeps review continuity when a preferred reviewer is rate-limited, unavailable, timed out, authentication-failed, or degraded.

It separates two concepts that are often incorrectly merged:

- **provider identity** — the engine that actually performs the review;
- **persona profile** — the requested reasoning style, rubric, and output contract.

A different provider may execute a requested persona, but the result must remain visibly proxy evidence. The router never claims that Qodo is CodeRabbit, Codex is Claude, or any other identity substitution.

## Example

```text
requested reviewer = coderabbit
requested profile  = coderabbit-style@1
coderabbit status  = RATE_LIMITED
selected executor  = qodo
result              = PROXY_HIGH
fallback reason     = RATE_LIMITED
```

The generated execution prompt states both identities and includes this invariant:

> Execute the requested rubric, but never claim to be the requested reviewer. A proxy result is not native approval and grants no merge authority.

## Routing contract

1. Bind the request to a full 40-character commit SHA.
2. Load the requested versioned persona profile.
3. Evaluate the requested provider first.
4. Reject unavailable providers and author conflicts.
5. Enforce profile compatibility and minimum evidence level.
6. Rank eligible fallback providers deterministically.
7. Allow at most one fallback hop in v0.1.
8. Record the real executor, requested reviewer, profile, reason, evidence level, candidate assessments, and `merge_authority: false`.

## Provider states

- `AVAILABLE`
- `DEGRADED`
- `RATE_LIMITED`
- `UNAVAILABLE`
- `AUTH_FAILED`
- `TIMED_OUT`

Only `AVAILABLE` and, when explicitly permitted, `DEGRADED` providers are eligible.

## Evidence levels

- `NATIVE` — the requested reviewer executes one of its native profiles.
- `PROXY_HIGH` — another provider executes the profile with compatibility of at least `0.85`.
- `PROXY` — compatibility meets the profile minimum, normally `0.70`.
- `DEGRADED` — reduced provider availability; accepted only when the request explicitly lowers its minimum evidence.

A fallback provider can never produce `NATIVE` evidence, even when it lists the same profile as native. Native identity is relative to the requested reviewer, not merely to the rubric.

## Deterministic score

Eligible proxy candidates are ranked by:

```text
compatibility
× historical_quality
× max(remaining_budget, 0.05)
× availability_weight
```

`availability_weight` is `1.0` for `AVAILABLE` and `0.60` for `DEGRADED`. Equal candidates are resolved by compatibility and then stable provider identifier ordering.

## Independence

When independent review is required, `author_engine` is excluded from eligibility. This prevents the engine that authored a change from becoming its only approving reviewer through a persona switch.

## Normalized findings

`NormalizedReviewFinding` records provider-neutral review output:

- stable finding code and P0–P3 severity;
- category and repository-relative path;
- concrete failure path and counterexample;
- smallest regression test and minimal remediation;
- confidence;
- actual executor, persona profile, and exact head SHA.

## Security and governance boundaries

The router is deterministic library logic only. It does not:

- invoke provider APIs;
- parse or trust vendor comments;
- spend provider quota;
- approve pull requests;
- merge code;
- retry through unbounded provider chains.

An integration layer may later feed trusted availability evidence into the router and execute the generated prompt. That integration must preserve the route decision unchanged and separately authenticate the resulting reviewer output.
