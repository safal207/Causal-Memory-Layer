# Information Quality Gates v0.1

This experimental contract adds three evidence-bounded information-quality checks before authority and action:

1. **semantic support** — is a claim supported, contradicted, or unresolved by authoritative evidence?
2. **bounded completeness** — are all aspects required by the declared decision schema covered?
3. **task relevance** — is the claim explicitly connected to at least one required decision aspect?

The contract deliberately avoids stronger claims that cannot be justified from the available evidence.

## Non-claims

This contract does **not**:

- prove metaphysical or universal truth;
- prove that the decision schema contains every fact that matters in the world;
- infer semantic relevance from raw text without an explicit decision scope;
- grant execution authority;
- replace provenance, lineage, current-state applicability, policy, or human approval.

It is a deterministic gate over trusted observations.

## Why these properties are separate

A memory can pass provenance and lineage checks and still be poor information for the current decision.

Examples:

```text
source is authentic
+ lineage is intact
+ environment still matches
+ authoritative evidence contradicts the claim
= do not use the claim
```

```text
claim is supported
+ only 2 of 5 required decision aspects are covered
= incomplete -> review
```

```text
claim is supported and complete in its own domain
+ it informs no required aspect of the current decision
= irrelevant -> exclude from this decision
```

## Semantic support

The evaluator consumes two explicit sets:

- `supporting_evidence`
- `contradicting_evidence`

The evidence identifiers are assumed to come from a trusted adapter or reviewer that has already classified the evidence relationship.

## Evidence binding (REQUIRED precondition)

Before semantic truth evaluation, every declared supporting and contradicting evidence identifier must be explicitly bound to the evaluation context. This is a **required precondition**, not pipeline guidance: unbound or mismatched evidence fails closed and can never produce `READY`.

Each binding carries four dimensions:

- `evidence_id` — the identifier listed in `supporting_evidence` / `contradicting_evidence`;
- `evaluated_item_id` — the item/claim the evidence actually supports or contradicts;
- `source_record_id` — the memory/source record the evidence comes from;
- `accepted_state_token` — the immutable state token the evidence was accepted against.

The observation declares the corresponding current identifiers (`evaluated_item_id`, `source_record_id`, `accepted_state_token`) and the `evidence_bindings` tuple. Validation rules:

- every declared evidence identifier must have a binding;
- every binding must match the observation's declared evaluated item, source record, and accepted state token;
- bindings for identifiers that are not declared are rejected;
- if evidence is declared but the observation does not declare the evaluation identifiers, the evaluation is rejected.

Failure semantics (fail closed):

```text
missing binding            -> EXCLUDE
item mismatch              -> EXCLUDE   (cross-claim substitution)
source-record mismatch     -> EXCLUDE   (cross-record substitution)
undeclared binding         -> EXCLUDE
scope undeclared           -> EXCLUDE
stale state-token mismatch -> REVIEW    (revalidation required)
```

`EXCLUDE` means the evidence cannot be treated as certified for the current claim. `REVIEW` means the evidence is correctly bound to the item and record but refers to an older accepted state, so revalidation is required. In no case does mismatched evidence reach `READY`.

Statuses:

```text
support only        -> SUPPORTED
contradiction only  -> CONTRADICTED
both                 -> UNRESOLVED / truth_conflicting_evidence
neither              -> UNRESOLVED / truth_no_authoritative_evidence
```

`SUPPORTED` therefore means **supported by the declared authoritative evidence bound to the current evaluation context**, not "universally true".

## Bounded completeness

Completeness is defined relative to `required_aspects` for a specific decision.

```text
required_aspects = {identity, amount, recipient}
observed_aspects = {identity, amount}

-> INCOMPLETE
-> completeness_missing:recipient
```

If `required_aspects` is empty, completeness is not reported as complete. It is:

```text
UNRESOLVED
completeness_scope_undefined
```

This prevents an undefined scope from producing a falsely perfect completeness result.

## Task relevance

Relevance is also decision-scoped.

`claim_aspects` declares which decision aspects the claim is intended to inform.

```text
required_aspects = {identity, amount, recipient}
claim_aspects    = {recipient}
-> RELEVANT
```

```text
required_aspects = {identity, amount, recipient}
claim_aspects    = {weather}
-> IRRELEVANT
-> relevance_no_required_aspect
```

No `claim_aspects` produces `UNRESOLVED`, not `IRRELEVANT`, because missing scope metadata is different from demonstrated irrelevance.

## Aggregate readiness

The aggregate result answers only whether the information may proceed to a separate authority check.

```text
binding integrity failure (missing/mismatched/undeclared/scope) -> EXCLUDE
binding stale state-token mismatch only                          -> REVIEW
CONTRADICTED or IRRELEVANT -> EXCLUDE
any unresolved dimension   -> REVIEW
INCOMPLETE                  -> REVIEW
SUPPORTED + COMPLETE + RELEVANT + bound evidence -> READY
```

`READY` never means "action allowed".

The intended composition is:

```text
retrieval reliability
    -> provenance / source integrity
    -> lineage / supersession
    -> current-state applicability
    -> evidence binding validation (REQUIRED precondition)
    -> evidence-bounded semantic support
    -> bounded completeness
    -> task relevance
    -> authority guard
    -> action
    -> evidence
```

## Frozen fixture

`tests/fixtures/information_quality_v0.1.json` freezes five cases:

1. supported + complete + relevant -> `READY`;
2. conflicting authoritative evidence -> `REVIEW`;
3. missing required aspect -> `REVIEW`;
4. explicitly irrelevant claim -> `EXCLUDE`;
5. contradicted claim -> `EXCLUDE`.

The fixture compares all three dimension statuses, aggregate readiness, and deterministic reasons.

Each case now declares the required evidence binding context (`evaluated_item_id`, `source_record_id`, `accepted_state_token`, `evidence_bindings`). The fixture is parsed with strict deterministic JSON: duplicate keys are rejected at every nesting level instead of silently keeping the last value.

## Relationship to classical information properties

This contract intentionally maps only a subset of classical information-quality properties:

- **reliability / truthfulness** -> evidence-bounded semantic support;
- **completeness** -> completeness relative to an explicit decision schema;
- **relevance / usefulness** -> relevance to an explicit task scope.

Other properties remain handled elsewhere or remain out of scope:

- actuality / timeliness -> current-state applicability and temporal bindings;
- provenance -> source integrity;
- causal origin -> lineage;
- accessibility / verifiability -> retrieval and coverage metrics;
- authorization -> authority guard.

The goal is not to rename textbook properties, but to make the parts that can be operationalized explicit, measurable, and fail-closed.
