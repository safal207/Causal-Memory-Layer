# CML Memory Proposal Queue Auditor v0.1

## Purpose

The Memory Proposal Queue Auditor is a **read-only planning tool** for the automatic CML Memory Learning Loop.

The learning loop intentionally produces one reviewable Memory Pack proposal per eligible merged pull request. That preserves source identity and requires explicit human review, but a sufficiently large open queue creates a second problem: review effort itself needs orientation.

The auditor answers:

> How large and structurally repetitive is the current proposal queue, and what is the safest review-planning transition before any individual memory is accepted or rejected?

It does **not** answer:

> Which Memory Packs are true, false, duplicates, safe to merge, or safe to delete?

## Current observed snapshot — 2026-08-15

The exact-title GitHub search for open automatic learning proposals reported:

```text
36 open proposals
```

The normalized repository fixture is:

`benchmarks/experimental/memory-proposal-queue-2026-08-15.json`

It is bound to CML main:

`90c7fdaaf31ad7c17ddc0c3c55b7ccd33f6affc2`

The oldest explicitly timestamped proposal in the current fixture is PR #191, created `2026-07-17T11:20:36Z`. The newest explicitly timestamped proposal is PR #284, created `2026-08-14T05:07:04Z`.

Only those timestamps are frozen in v0.1; missing timestamps for the other proposals are **not invented**. Age coverage is therefore explicitly `PARTIAL`.

## Input contract

Schema:

```text
cml.memory-proposal-queue.snapshot.v0.1
```

Each proposal carries its distinct source identity:

```text
proposal_pr
source_pr
source_merge
pack_id
created_at | null
state = open
draft = true
lesson_status = proposed
visibility = team
contains_private_data = true
merge_authority = false
execution_authority = false
```

The snapshot fails closed when:

- `reported_total_count` does not equal the number of normalized proposals;
- proposal, source PR, source merge, or pack identity is duplicated;
- any proposal claims merge or execution authority;
- proposal state escapes the automatic-learning contract;
- a timestamp is impossible relative to the snapshot capture time.

## Queue pressure bands

v0.1 uses review-planning bands only:

```text
0–9    BOUNDED_REVIEW_PRESSURE
10–19  ELEVATED_REVIEW_PRESSURE
20–29  HIGH_REVIEW_PRESSURE
30+    CRITICAL_REVIEW_PRESSURE
```

These bands are not truth, safety, or merge scores. They only choose the granularity of the next review-planning step.

At `HIGH` or `CRITICAL` pressure the recommended transition is:

```text
QUEUE_LEVEL_GROUP_REVALIDATE_THEN_REVIEW
```

That means:

1. plan review at queue level;
2. preserve every distinct pack identity;
3. revalidate selected packs against current applicability and information-quality contracts;
4. then perform explicit human acceptance/rejection review per pack.

## Structural repetition vs semantic duplication

Every automatic proposal currently shares the same review envelope:

```text
open
draft
status=proposed
visibility=team
contains_private_data=true
merge_authority=false
execution_authority=false
```

The auditor measures repetition of that **envelope**, not similarity of the Memory Pack contents.

Invariant:

> Structural review-envelope repetition ≠ semantic Memory Pack duplication.

Accordingly v0.1 emits:

```text
semantic_duplicate_status = NOT_MEASURED
semantic_duplicate_claim = false
```

No automatic grouping result may be used to merge, close, accept, delete, or deduplicate a Memory Pack.

## Age boundary

Queue age can identify review debt, but it does not invalidate evidence.

Invariant:

> Old ≠ stale; stale ≠ invalid; invalid ≠ authorized to delete.

Current-main ancestry and applicability are therefore reported separately as:

```text
ancestry.status = NOT_MEASURED
```

A later exact-main revalidation pass may add commit ancestry/current-contract evidence, but v0.1 does not infer it from PR age or PR number.

## Output contract

Schema:

```text
cml.memory-proposal-queue.audit.v0.1
```

Every result remains:

```text
mode = REVIEW_ADVISORY_ONLY
authority_granted = false
merge_authority = false
close_authority = false
acceptance_authority = false
policy_mutation_authority = false
```

The output includes:

- complete queue count;
- queue-pressure band;
- distinct source/pack identity counts;
- explicit age coverage and known age facts;
- structural review-envelope repetition;
- `NOT_MEASURED` semantic-duplicate status;
- `NOT_MEASURED` ancestry status;
- a deterministic snapshot digest;
- a bounded next safe transition.

## Relationship to Graph–Field Dynamics

RESONANCE Graph–Field Dynamics prospectively selected `cml-memory-proposal-pressure` over a FIFO maintenance baseline. The first investigation saw seven recent proposals, but a complete exact-title inventory later showed **36** open automatic proposals.

That is an important falsification lesson:

> Field orientation may correctly identify a system-level hotspot while the first local observation still undercounts its extent.

The Queue Auditor exists to turn that hotspot into an inspectable CML-native measurement rather than making GFD itself the authority over CML memory policy.

## Non-claims

The auditor does not claim:

- semantic equivalence between packs;
- correctness of generated lessons;
- current applicability of historical evidence;
- source-commit ancestry relative to current main;
- permission to merge, close, accept, reject, delete, or rewrite proposals;
- permission to change the Memory Learning Loop policy;
- proof that a smaller queue is intrinsically better.

## Next boundary

After v0.1 queue measurement, the natural next experiment is a **read-only queue grouping/revalidation planner** that uses explicit source metadata and current CML trust gates while preserving one decision record per Memory Pack.
