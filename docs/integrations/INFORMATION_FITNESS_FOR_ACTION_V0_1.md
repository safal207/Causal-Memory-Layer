# Information Fitness for Action v0.1

This contract composes two already-separated questions:

1. **Is the historical memory still applicable to the current state?**
2. **Is the information quality sufficient for the current decision?**

It then answers one narrower transition question:

> Is this information fit to be handed to a separate authority check?

It does **not** answer whether an action is authorized.

## Core invariant

```text
memory applicability = MATCH
    +
information quality = READY
    -> READY_FOR_AUTHORITY_CHECK
    != action authorized
```

A positive fitness result only opens the next gate.

## Statuses

```text
NOT_FIT
REVIEW_REQUIRED
READY_FOR_AUTHORITY_CHECK
```

Precedence is fail-closed:

```text
NOT_FIT -> REVIEW_REQUIRED -> READY_FOR_AUTHORITY_CHECK
```

## Composition rules

### NOT_FIT

Information is not fit to influence an authority decision when:

- applicability is `REJECT`, `UNRESOLVABLE`, `ORPHAN`, or `DRIFT`; or
- information quality is `EXCLUDE`.

Examples:

- source digest changed;
- authoritative source disappeared;
- caller forged trust metadata;
- claim is contradicted;
- claim is explicitly irrelevant to the decision.

### REVIEW_REQUIRED

Human or adapter revalidation is required when:

- applicability is `REVALIDATE`; or
- information quality is `REVIEW`.

Examples:

- lineage was superseded;
- current environment changed;
- evidence conflicts;
- required decision aspects are missing.

### READY_FOR_AUTHORITY_CHECK

Only this pair reaches the authority layer:

```text
ApplicabilityStatus.MATCH
+
QualityReadiness.READY
```

Even then, the contract explicitly reports:

```text
authorizes_action = false
```

Authority remains a separate decision based on actor, policy, approval, scope,
risk, and other permission constraints.

## Why this layer exists

Without a composition gate, a system can accidentally treat any one positive
property as sufficient:

```text
source matches -> act
```

or:

```text
claim is supported -> act
```

Both are unsafe shortcuts.

The composed path is instead:

```text
retrieval
  -> provenance / source integrity
  -> lineage / supersession
  -> current-state applicability
  -> evidence-bounded semantic support
  -> bounded completeness
  -> task relevance
  -> information fitness
  -> authority
  -> action
  -> evidence
```

## Frozen fixture

`tests/fixtures/information_fitness_v0.1.json` freezes six cases:

1. `MATCH + READY -> READY_FOR_AUTHORITY_CHECK`;
2. `REVALIDATE + READY -> REVIEW_REQUIRED`;
3. `MATCH + REVIEW -> REVIEW_REQUIRED`;
4. `DRIFT + READY -> NOT_FIT`;
5. `MATCH + EXCLUDE -> NOT_FIT`;
6. blocking applicability takes precedence over quality review.

Reasons from upstream layers are preserved with deterministic namespaces:

```text
applicability:<reason>
quality:<reason>
```

This makes the composed verdict auditable without collapsing the underlying
cause.

## Non-claims

This contract does not prove truth, completeness, safety, or permission in the
abstract. It only composes explicit upstream observations into a deterministic
handoff decision for the authority layer.
