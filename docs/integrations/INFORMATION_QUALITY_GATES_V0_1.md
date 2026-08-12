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

Statuses:

```text
support only        -> SUPPORTED
contradiction only  -> CONTRADICTED
both                 -> UNRESOLVED / truth_conflicting_evidence
neither              -> UNRESOLVED / truth_no_authoritative_evidence
```

`SUPPORTED` therefore means **supported by the declared authoritative evidence**, not "universally true".

## Evidence binding (REQUIRED precondition)

Every evidence identifier that asserts support or contradiction must be bound to
the item it was classified against and to the accepted-state token in effect at
classification time.

Binding dimensions:

- `evidence_id` — the identifier also present in `supporting_evidence` or `contradicting_evidence`;
- `evaluated_item_id` — the information item the evidence speaks to;
- `source_record_id` — the record the evidence came from;
- `accepted_state_token` — the token of the accepted state the evidence was classified under.

This is a **REQUIRED precondition** enforced by the evaluator, not pipeline
guidance. When bindings are supplied:

- they must bind exactly the declared evidence identifiers;
- the observation must declare its own `evaluated_item_id` and `accepted_state_token`;
- every binding must match both observation identifiers.

Mismatched evidence fails closed:

```text
evidence bound to claim A
+ evaluating claim B
-> EXCLUDE
-> evidence_binding_item_mismatch:<evidence_id>

evidence bound to state token T1
+ evaluating under token T2
-> EXCLUDE
-> evidence_binding_state_mismatch:<evidence_id>
```

Mismatched evidence can **never** produce `READY`. The frozen v0.1 fixture
remains valid as the legacy string-only contract; new integrations must supply
bindings.

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
mismatched evidence binding   -> EXCLUDE
CONTRADICTED or IRRELEVANT -> EXCLUDE
any unresolved dimension   -> REVIEW
INCOMPLETE                  -> REVIEW
SUPPORTED + COMPLETE + RELEVANT -> READY
```

`READY` never means "action allowed".

The intended composition is:

```text
retrieval reliability
    -> provenance / source integrity
    -> lineage / supersession
    -> current-state applicability
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
