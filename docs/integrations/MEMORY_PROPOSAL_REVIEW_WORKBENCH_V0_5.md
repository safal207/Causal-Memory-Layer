# Memory Proposal Human Review Workbench v0.5

Status: experimental, review-only.

## Purpose

The Human Review Workbench turns the frozen Semantic Acceptance v0.4 intake into a deterministic queue that a human can actually inspect.

It does **not** decide whether a Memory Pack is true, useful, accepted, rejected, mergeable, closable, or executable. It orders review attention and preserves exact evidence bindings.

```text
live queue
  -> v0.1 audit
  -> v0.2 canonical planner
  -> v0.3 live revalidation
  -> v0.4 frozen semantic packet
  -> v0.5 human review workbench
  -> human semantic submission
  -> separate authority check
```

## Review card

One workbench card is preserved for every frozen semantic packet.

Each card binds:

- packet ID;
- planner decision ID;
- proposal PR;
- source PR;
- Memory Pack ID;
- exact current-main revision;
- generated situation, action, and lesson text from the frozen Memory Pack;
- generated lesson confidence;
- source-PR changed paths;
- net path state at source merge versus current main;
- machine gate result and evidence drift;
- exact gate, lineage, and workbench context evidence references;
- an intentionally incomplete Semantic Acceptance v0.4 submission template.

The submission template pre-binds machine-controlled identity fields but leaves these human fields empty:

```text
reviewer_id = null
reviewed_at = null
verdict = null
rationale = null
```

No workflow fabricates a human semantic verdict.

## Current path-state signal

For every file changed by the source PR, the live collector compares the state at the exact source merge with the state at the frozen current-main revision.

States:

```text
SAME_AS_SOURCE_MERGE
DIVERGED_FROM_SOURCE_MERGE
MISSING_OR_RENAMED_ON_CURRENT_MAIN
```

A source PR that intentionally removed a path uses an explicit `ABSENT` state token. If the path remains absent on current main, its net state matches the source merge; if it reappears, the state diverges.

This comparison is a **net state comparison**, not historical-touch evidence. A matching blob cannot prove that a path was never changed and later reverted.

## Priority classes

v0.5 deliberately does not invent a probability or universal score. Review ordering is lexicographic:

```text
P0_SOURCE_SCOPE_MISSING
P1_SOURCE_SCOPE_DIVERGED
P2_REVIEW_CONTEXT_DRIFT
P3_OPERATIONAL_EVIDENCE_REFRESH
P4_CURRENT_SCOPE_MATCH
```

Meaning:

- `P0_SOURCE_SCOPE_MISSING`: at least one source path is no longer present at its recorded path on current main;
- `P1_SOURCE_SCOPE_DIVERGED`: at least one source path currently has a different state from the source merge;
- `P2_REVIEW_CONTEXT_DRIFT`: code-path state matches, but descriptive PR or review evidence changed;
- `P3_OPERATIONAL_EVIDENCE_REFRESH`: only operational check evidence changed;
- `P4_CURRENT_SCOPE_MATCH`: no higher-priority signal was observed.

Within one class, the deterministic tiebreak order is:

1. lower generated lesson confidence;
2. broader source changed-path count;
3. older Memory Pack creation time;
4. proposal PR number.

These rules order **human attention only**.

```text
higher review priority
!= higher truth probability
!= semantic invalidity
!= acceptance authority
```

## Human submission boundary

The workbench does not replace the v0.4 Semantic Acceptance validator.

A human still submits exactly one of:

```text
ACCEPT
REJECT
DEFER
```

against the frozen packet, exact current-main revision, and exact reviewed evidence set.

Even then:

```text
ACCEPT -> semantic support evidence -> separate acceptance authority check
REJECT -> semantic rejection evidence -> separate rejection/closure authority check
DEFER  -> no semantic conclusion -> wait for more evidence/review
```

The workbench itself never performs those later authority transitions.

## Authority invariant

Every v0.5 result and card is fixed to:

```text
authority_granted = false
merge_authority = false
close_authority = false
acceptance_authority = false
execution_authority = false
policy_mutation_authority = false
review_completed = false
```

## Non-claims

v0.5 does not claim that:

- a missing or diverged source path invalidates a lesson;
- a matching source path proves a lesson is still useful;
- mutable review/check evidence is equivalent to source-code drift;
- queue rank measures truth, importance, confidence, or business value;
- generated Memory Pack confidence is human confidence;
- a pre-filled submission template is a completed review;
- a human semantic verdict grants repository authority.

The intended boundary is:

> **Machine evidence decides what must be inspected. The workbench decides only inspection order. Human judgment records meaning. Authority remains a later and separate transition.**
