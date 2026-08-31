# Memory Proposal Queue Revalidation v0.3

Status: **experimental / read-only**.

This layer turns the open automatic Memory Proposal queue into individually evidence-bound revalidation records without granting acceptance, merge, close, execution, or policy authority.

## Boundary

```text
live GitHub facts
  -> strict frozen Memory Pack identity validation
  -> current source replay for diagnostics
  -> immutable source-core comparison
  -> mutable-evidence drift classification
  -> current-main ancestry observation
  -> canonical CML applicability
  -> conservative information quality
  -> canonical information fitness
  -> Planner v0.2
  -> separate human acceptance review
```

The network collector is not a trust oracle. It gathers GitHub observations only. The pure adapter consumes normalized observations and reuses existing CML applicability, information-quality, and information-fitness gates.

## Three identities must not be collapsed

v0.3 separates three different questions.

### 1. Frozen Memory Pack identity

The proposal's existing `pack_id` is strictly revalidated with the source-owned retrieval core. This proves that the frozen proposal artifact itself has not been silently rewritten.

### 2. Immutable source identity

Current applicability is not based on full Memory Pack equality. The stable source core binds:

```text
repository
+ source PR number
+ exact source head SHA
+ exact source merge SHA
+ source-files digest
```

These fields describe the code/source transition whose lesson was generated.

### 3. Mutable evidence

The following remain evidence, but are not immutable source-code identity:

```text
source-pr       # includes mutable PR narrative metadata/body
source-reviews  # appendable review history
source-checks   # rerunnable / latest operational check state
```

Changes in these components require review and remain visible in evidence. They do not by themselves establish that the source code transition changed.

## Full-pack replay is diagnostic, not applicability authority

The collector still replays the source-owned `memory_learning_core.build_memory_pack()` against current GitHub observations and records:

```text
original pack_id == replayed pack_id
```

But this is deliberately diagnostic. A full-pack mismatch can be caused by mutable PR narrative, later reviews, or rerun/replaced check results.

Therefore:

```text
full pack replay drift != immutable source drift
immutable source match != semantic acceptance
```

## Verification-of-verifier history

The first live v0.3 pass observed:

```text
full_pack_replay_match = 0 / 36
```

Treating full pack identity as current source identity would have classified all 36 proposals as `DRIFT / NOT_FIT`.

Instead of accepting that interpretation, the verifier was decomposed by evidence component. The component-level observation showed:

```text
source-checks   changed in 36 / 36
source-pr       changed in  8 / 36
source-reviews  changed in  6 / 36
source-files    changed in  0 / 36
source-merge    changed in  0 / 36
```

Representative `source-pr` mismatches were traced to post-merge PR-body updates such as appended CodeRabbit release notes while exact source head/files/merge remained unchanged.

The resulting correction was not to ignore drift. It was to move mutable narrative/operational evidence out of immutable source identity while preserving every observed difference for review.

This is the intended verifier loop:

```text
FAIL
  -> locate first meaningful divergence
  -> classify verifier granularity
  -> refine evidence boundary
  -> replay
```

## Final live result on the refined boundary

Verified live run on semantic head:

```text
head  = d48bbc09bf6ac12ce9ede7f056bfeaf368d51680
run   = 31889575661
job   = 95023764300
```

Observed queue:

```text
proposal_count                     = 36
planner_record_count               = 36
stable_source_core_match_count     = 36
stable_source_core_drift_count     = 0
source_ancestor_of_main_count      = 36
source_not_ancestor_of_main_count  = 0
```

Canonical CML outcomes:

```text
Applicability: REVALIDATE       = 36
Quality:       REVIEW           = 36
Fitness:       REVIEW_REQUIRED  = 36
```

Mutable/full-pack diagnostics remain:

```text
full_pack_replay_match_count       = 0
full_pack_replay_drift_count       = 36
mutable_evidence_drift_count       = 36
descriptive_pr_metadata_drift      = 8
operational_evidence_drift         = 36
source-checks mismatch             = 36
source-pr mismatch                 = 8
source-reviews mismatch            = 6
```

No semantic acceptance evidence was collected:

```text
semantic_acceptance_evidence = NOT_COLLECTED
```

So even though all 36 immutable source cores remain intact and all 36 source merges remain ancestors of current main, **none is automatically accepted**. Historical environment differs from current main and semantic acceptance is still a separate review decision.

The live evidence artifact from this semantic-head run was uploaded by the workflow as `cml-memory-queue-revalidation-31889575661-1`.

## Semantic acceptance is intentionally missing

The quality gate requires bounded evidence for:

1. `pack_identity`
2. `stable_source_core`
3. `current_main_ancestry`
4. `mutable_evidence`
5. `semantic_acceptance`

The collector can observe the first four. It deliberately does not manufacture independent semantic acceptance evidence. Consequently, even an intact current source core remains `QualityReadiness.REVIEW` and cannot skip human acceptance review.

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
stable source matches + stable source drift == live proposal count
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
