# Memory Proposal Semantic Acceptance Intake v0.4

Status: **experimental / human-review intake only**.

v0.4 starts where live Queue Revalidation v0.3 intentionally stops. v0.3 can prove pack identity, immutable source bindings, current-main ancestry, mutable evidence drift, canonical applicability, and information-quality state. It deliberately does not manufacture semantic acceptance evidence.

v0.4 freezes the exact machine evidence a human is being asked to judge and validates a later human verdict against that frozen packet.

## Lifecycle

```text
live GitHub facts
  -> Queue Revalidation v0.3
  -> Planner v0.2 decision
  -> frozen Semantic Review Packet v0.4
  -> human review
  -> bound Semantic Review Record v0.4
  -> separate authority check
```

The semantic review record is evidence. It is **not** repository authority.

## Why the packet must be frozen

A review such as “I accept this memory” is unsafe if it is not bound to the exact state that was reviewed. Between review and use, any of these may change:

- current `main`;
- the Planner decision;
- the Memory Pack;
- the machine revalidation observation;
- evidence references.

Therefore every packet binds:

```text
decision_id
+ proposal_pr
+ source_pr
+ source_merge
+ pack_id
+ current_main_revision
+ observation_digest
+ exact gate evidence refs
+ exact lineage evidence refs
```

The resulting `packet_id` is deterministic.

## Packet states

Canonical information fitness controls whether semantic review is appropriate:

```text
REVIEW_REQUIRED
  -> PENDING_HUMAN_SEMANTIC_REVIEW

NOT_FIT
  -> BLOCKED_PENDING_NEW_EVIDENCE_OR_CONTEXT

READY_FOR_AUTHORITY_CHECK
  -> SEPARATE_AUTHORITY_REVIEW_ONLY
```

A `NOT_FIT` packet cannot use a human semantic verdict as a shortcut around missing or contradictory machine evidence.

## Human submission contract

A valid human submission must bind the exact packet and provide:

```text
packet_id
decision_id
pack_id
observed_main_revision
reviewer_id
reviewed_at
verdict
rationale
reviewed_gate_evidence_refs
optional additional_evidence_refs
```

The frozen gate evidence refs must be reviewed exactly. `observed_main_revision` must equal the packet revision. Stale or misbound review submissions fail closed.

Allowed verdicts:

```text
ACCEPT
REJECT
DEFER
```

Their effects are intentionally bounded:

```text
ACCEPT
  -> SEMANTIC_SUPPORT_RECORDED
  -> SEPARATE_ACCEPTANCE_AUTHORITY_CHECK_REQUIRED

REJECT
  -> SEMANTIC_REJECTION_RECORDED
  -> SEPARATE_REJECTION_OR_CLOSURE_AUTHORITY_CHECK_REQUIRED

DEFER
  -> SEMANTIC_REVIEW_DEFERRED
  -> AWAIT_NEW_EVIDENCE_OR_FURTHER_HUMAN_REVIEW
```

## Critical authority boundary

Even a valid human `ACCEPT` does **not** mean the Memory Pack is accepted.

Even a valid human `REJECT` does **not** close or delete its proposal.

Every packet and every review record remains:

```text
authority_granted = false
merge_authority = false
close_authority = false
acceptance_authority = false
execution_authority = false
policy_mutation_authority = false
state_mutation_performed = false   # review record
```

Any repository mutation requires a later, separate authority-bearing path.

## Live v0.4 evidence contract

The v0.4 workflow does **not** invent human reviews. It must end with all currently review-required live packets pending:

```text
packet_count == Planner record_count
pending_human_review_count == count(REVIEW_REQUIRED)
completed_human_review_count == 0
```

The artifact contains the underlying v0.3 live evidence plus `semantic-intake.json` and a SHA256 manifest.

## Non-claims

- packet generation is not semantic review;
- `ACCEPT` is not merge or acceptance authority;
- `REJECT` is not closure or deletion authority;
- one human reviewer does not establish universal truth;
- historical source integrity does not prove a lesson remains optimal;
- semantic review cannot repair immutable source drift or contradictory evidence.

## System invariant

> **Machine evidence constrains what may be reviewed. Human judgment records meaning. Authority remains separate from both.**
