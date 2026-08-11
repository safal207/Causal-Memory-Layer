# Memory Lineage and Supersession v0.1

This extension adds a third question between source integrity and current-environment applicability:

1. **Was this memory valid evidence of what happened?**
2. **Are the records it was derived from still live and unchanged?**
3. **Is that historical evidence safe to use in the current environment?**

A derived memory can remain historically accurate and still become unsafe to reuse. For example, a consolidation summary may still match its own source after one upstream record was superseded, retired, erased, or changed. Source integrity alone cannot detect that case because the derived record itself did not drift.

## Core invariant

```text
derived memory source still matches
        +
one lineage dependency was superseded / retired / erased / changed
        != current authority

instead:
        -> REVALIDATE
        -> re-derive or refuse
        -> only then may an action continue
```

`REVALIDATE` is used rather than adding a seventh verdict. The historical derived memory is not rewritten as false; its present applicability has become uncertain because the causal lineage that justified it changed.

## Deterministic ordering

The six existing statuses remain unchanged:

```text
REJECT -> UNRESOLVABLE -> ORPHAN -> DRIFT -> REVALIDATE -> MATCH
```

Checks compose in this order:

```text
caller trust namespace
    -> source integrity
    -> lineage / supersession
    -> current environment
    -> MATCH
```

Source-integrity failures still win over lineage or environment revalidation. Lineage and environment failures both produce `REVALIDATE`; when both apply, their reasons are combined and stably sorted.

## Lineage dependency observation

`LineageDependency` records the current state of one record used to derive the memory:

- `dependency_id`
- `state`: `active`, `superseded`, `retired`, or `erased`
- `expected_digest`
- `observed_digest`

Rules:

- non-`active` dependency -> `REVALIDATE`
- active dependency with a changed digest -> `REVALIDATE`
- active dependency without enough digest evidence -> `REVALIDATE`
- duplicate dependency identity -> `REVALIDATE`
- all active dependencies with matching digests -> lineage does not block `MATCH`

The check is local to the memory store. Supersession and erasure therefore remain detectable even when external source re-fetch coverage is low.

## Why lineage is separate from source integrity

Source integrity asks whether the **derived record itself** still matches its authoritative origin.

Lineage asks whether the **causal inputs used to derive that record** are still valid members of the store's current history.

Those scopes differ. A summary can have a perfectly matching digest while carrying forward content from a parent record that has since been erased. Treating both dimensions as one score would hide the remedy: the derived record must be re-derived or refused, not merely re-fetched.

## Benchmark contract

`tests/fixtures/memory_lineage_v0.1.json` is frozen around five included cases:

- parent superseded
- parent erased
- one parent retired in a multi-parent derivation
- parent content changed
- active parent cannot be deterministically re-verified

Every included case carries a negative control that restores the relevant parent to an active, matching state and must return `MATCH`.

The fixture also contains one deliberately excluded case (`lineage_adapter_unavailable`) so the harness must report exclusions explicitly rather than silently converting missing observations into clean benchmark numbers.

The expected benchmark accounting is:

```text
included = 5
excluded = 1
negative controls = 5
```

## Coverage

The original applicability metrics remain useful:

- `locator_coverage`
- `refetch_verification_coverage`
- `source_enumeration_coverage`
- `environment_binding_coverage`

Lineage-aware systems should additionally report:

- `lineage_verification_coverage` — fraction of derived records whose declared dependencies can be checked for current membership/state and digest continuity.

This metric must not be inferred from schema presence. It should be measured from records that can actually be evaluated.

## Compatibility

This is an additive v0.1 extension. Existing callers that do not supply `lineage` preserve the previous Current-State Applicability behavior. The accepted Memory Pack schema is unchanged.

The intended composed contract is:

```text
retrieval reliability
    -> source integrity
    -> lineage / supersession
    -> current-state applicability
    -> authority guard
    -> action
    -> evidence
```
