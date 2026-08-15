# Memory Proposal Queue Revalidation v0.3

Status: **experimental / read-only**.

This layer turns the open automatic Memory Proposal queue into individually evidence-bound revalidation records without granting acceptance, merge, close, execution, or policy authority.

## Boundary

```text
live GitHub facts
  -> strict Memory Pack identity validation
  -> deterministic source replay
  -> current-main ancestry observation
  -> canonical CML applicability
  -> conservative information quality
  -> canonical information fitness
  -> Planner v0.2
  -> separate human acceptance review
```

The network collector is not a trust oracle. It only gathers GitHub observations. The pure adapter consumes those observations and reuses existing CML gates.

## Source replay

For each open `memory: learn from merged PR #N` proposal, the collector reads:

- proposal PR identity and body contract;
- exact proposal head and Memory Pack JSON;
- source merged PR;
- source changed files;
- source reviews without using review bodies in the Memory Pack builder;
- exact source-head check runs;
- source merge vs current `main` compare state.

The original Memory Pack is strictly validated with the existing retrieval-core schema and `pack_id` algorithm. The source-owned `memory_learning_core.build_memory_pack()` is then replayed against the currently fetched source snapshots.

```text
original pack_id == replayed pack_id
```

means the normalized provenance bundle still reproduces. It does **not** mean the generated lesson is semantically accepted or currently optimal.

A replay mismatch is source snapshot drift and enters canonical applicability as `DRIFT`.

## Current environment

The historical environment is bound to the Memory Pack source merge. The current environment is bound to the live `main` SHA. Therefore an older but faithfully reproduced Memory Pack normally requires `REVALIDATE` before reuse.

If the source merge is no longer an ancestor of current main, the adapter records a revalidation lineage signal. This is not deletion/closure authority.

## Semantic acceptance is intentionally missing

The quality gate requires four bounded aspects:

1. `pack_identity`
2. `source_replay`
3. `current_main_ancestry`
4. `semantic_acceptance`

The collector can observe the first three. It deliberately does not manufacture independent semantic acceptance evidence. Consequently, even a perfect structural replay remains `QualityReadiness.REVIEW`, and therefore cannot skip human acceptance review.

## Live outputs

The workflow writes:

- `queue-snapshot.json`
- `queue-audit.json`
- `planner-input.json`
- `planner-result.json`
- `summary.json`

Coverage must satisfy:

```text
live proposal count == planner record count
```

Every Planner record remains independent. v0.3 uses `source-pr:<N>` as the lineage root unless future evidence proves a broader shared lineage. Similar templates are not enough to merge groups.

## Authority invariant

```text
mode = REVIEW_ADVISORY_ONLY
authority_granted = false
merge_authority = false
close_authority = false
acceptance_authority = false
execution_authority = false
policy_mutation_authority = false
```

`READY_FOR_AUTHORITY_CHECK` is not acceptance. `NOT_FIT` is not deletion authority. Structural source replay is not semantic truth.
