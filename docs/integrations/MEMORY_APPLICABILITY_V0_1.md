# Memory Current-State Applicability v0.1

CML separates two questions that are easy to collapse:

1. **Was this memory valid evidence of what happened?**
2. **Is that historical evidence safe to use in the current environment?**

A memory can remain historically valid while the world around it changes. A branch can move, a policy can be replaced, a tenant can differ, an API or model can change, a target state can drift, or a time-bound authorization can expire. In those cases CML does not rewrite history as false. It returns `REVALIDATE` before the memory may influence a current action.

## Deterministic verdicts

| Verdict | Meaning | Default action |
| --- | --- | --- |
| `MATCH` | Source integrity matches and all required/current environment bindings are satisfied. | May proceed to the next guard. |
| `DRIFT` | Re-fetchable source exists but its observed digest differs from the stored digest. | Refresh/reconcile evidence. |
| `ORPHAN` | Re-fetchable source was deleted or is no longer present. | Quarantine from current-action authority. |
| `UNRESOLVABLE` | Source cannot be re-fetched or cannot be verified deterministically. | Abstain from treating it as current authority. |
| `REJECT` | Caller attempted to supply reserved internal trust/provenance state. | Deny the attempt. |
| `REVALIDATE` | Historical evidence is intact, but current authoritative environment no longer matches or is not sufficiently bound to the environment it was validated against. | Re-check current state before action. |

The core precedence is fail-closed:

```text
REJECT -> UNRESOLVABLE -> ORPHAN -> DRIFT -> REVALIDATE -> MATCH
```

## Environment binding

`EnvironmentBinding` can bind a memory to any subset of:

- repository
- branch
- commit SHA
- workspace
- actor
- tenant
- policy digest
- target-state digest
- API version
- model version
- observation time and `valid_until`

Most dimensions are optional and only fields explicitly bound by historical memory must match. If a historically bound field is missing from current authoritative state, the result is `REVALIDATE`, not a silent match.

Repository and commit SHA are stricter because they anchor evidence to an immutable code context. If current authoritative state supplies `repository` or `commit_sha` but historical evidence did not bind the corresponding dimension, CML returns `REVALIDATE` with `environment_unbound:<dimension>`. This prevents stale-SHA acceptance and cross-repository substitution from reaching `MATCH` merely because the source digest itself still matches.

## Source identity is not source reachability

A populated source label is not enough. `agent:scholar`, for example, may identify the writer but does not identify content that can be fetched again. `SourceObservation.refetchable` is therefore explicit.

A source is considered verified only when the adapter supplies:

- a locator,
- `refetchable=true`,
- confirmed existence,
- the expected digest, and
- the currently observed digest.

The pure applicability core performs no network I/O. Git, GitHub, filesystem, database, DOI, URL, or other adapters are responsible for producing the authoritative observation. This keeps the verdict deterministic and testable.

Source-integrity failures are evaluated before environment drift. If the source is unresolvable, orphaned, or digest-drifted while the environment also changed, the source verdict wins. This prevents a weaker `REVALIDATE` result from masking stale or missing historical evidence.

## Reserved internal trust state

Caller metadata cannot grant itself authority. These keys are reserved:

- `warrant`
- `environment_verified`
- `provenance_verified`
- `source_verified`
- `applicability_verdict`
- every key beginning with `_cml_`

If untrusted caller metadata contains one of those keys, the verdict is `REJECT` before source or environment checks run.

This rule prevents the class of failure where a caller sets metadata that the library later mistakes for its own internal decision.

## Historical evidence vs current authority

The intended invariant is:

```text
historical evidence valid
        +
current environment differs
        -> REVALIDATE
        -> current-state check
        -> only then may an action continue
```

`REVALIDATE` does **not** mean the historical memory is false. It means historical truth is insufficient evidence for present authority.

## Coverage metrics

Implementations should report these separately rather than collapse them into one provenance percentage:

1. `locator_coverage` — fraction with an origin locator.
2. `refetch_verification_coverage` — fraction whose origin can be fetched and digest-compared.
3. `source_enumeration_coverage` — fraction whose authoritative source can be enumerated to detect deletions/orphans.
4. `environment_binding_coverage` — fraction bound to enough current-state dimensions to make reuse decisions meaningful.

The fixture `tests/fixtures/memory_applicability_v0.1.json` freezes all six verdicts, repository substitution, missing immutable PR bindings, source/environment collision precedence, environment drift, and forged internal metadata.

## Compatibility

This v0.1 layer is intentionally additive. It does not change the existing accepted Memory Pack schema or reinterpret a Memory Pack's content-addressed historical identity. It is designed to run after historical/source validation and before memory-derived state is allowed to influence a current action.
