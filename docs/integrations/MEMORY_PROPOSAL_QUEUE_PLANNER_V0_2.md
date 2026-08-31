# Memory Proposal Queue Grouping / Revalidation Planner v0.2

Status: experimental, read-only, review-advisory only.

## Purpose

The v0.1 Queue Auditor answers a queue-level question: how large and structurally repetitive is the open automatic Memory Pack proposal queue?

The v0.2 Planner answers the next narrower question:

> Given explicit per-pack CML applicability and information-quality results, how can review work be grouped without collapsing Memory Pack identity or granting acceptance authority?

The planner is not a new trust gate. It imports and reuses the existing CML information-fitness composition.

## Canonical trust composition

For each Memory Pack, the caller supplies source-owned serialized results from:

- `ApplicabilityResult` / `ApplicabilityStatus`;
- `InformationQualityResult` / `QualityReadiness`;
- explicit lineage evidence references;
- explicit gate evidence references.

The planner reconstructs those typed results and calls:

```python
evaluate_information_fitness(
    applicability=applicability,
    quality=quality,
)
```

The canonical precedence remains owned by `cml.integrations.information_fitness`:

```text
NOT_FIT -> REVIEW_REQUIRED -> READY_FOR_AUTHORITY_CHECK
```

The planner does not duplicate or override that precedence.

A caller-provided `claimed_fitness_status` must equal the canonical recomputation or the input fails closed.

## Input contract

```text
schema = cml.memory-proposal-queue.revalidation-input.v0.2
source_audit_schema = cml.memory-proposal-queue.audit.v0.1
source_audit_digest = sha256:<digest>
current_main_revision = <40-char Git SHA>
captured_at = <timezone-aware ISO-8601 timestamp>
synthetic = true|false
expected_record_count = N
records = [...]
```

Each record preserves:

```text
proposal_pr
source_pr
source_merge
pack_id
lineage_root_id
lineage_evidence_refs[]
gate_evidence_refs[]
applicability { status, reasons[] }
quality {
  semantic_truth,
  completeness,
  relevance,
  readiness,
  reasons[]
}
claimed_fitness_status
```

`lineage_root_id` must be explicit and evidence-backed. The planner never infers lineage from PR number, title similarity, age, file path, or shared review-envelope structure.

## One decision record per pack

The output schema is:

```text
cml.memory-proposal-queue.revalidation-plan.v0.2
```

Every input Memory Pack receives a distinct deterministic `decision_id` bound to:

- pack identity;
- explicit lineage root;
- current main revision;
- applicability status;
- quality readiness;
- canonical information-fitness status;
- lineage and gate evidence refs.

Even when multiple packs share a review group, their decision records remain independent.

## Grouping rule

Review groups are formed only by:

```text
explicit lineage_root_id × canonical information-fitness status
```

Example:

```text
pr-contracts × READY_FOR_AUTHORITY_CHECK
pr-contracts × REVIEW_REQUIRED
security × REVIEW_REQUIRED
security × NOT_FIT
```

The same lineage can therefore appear in more than one group when current trust posture differs.

Every group is fixed to:

```text
scope = REVIEW_ERGONOMICS_ONLY
semantic_merge = false
group_decision_authority = false
```

A group does not become a new Memory Pack, a shared verdict, a deduplication claim, or an acceptance unit.

## Review routes

Canonical fitness is mapped only to a review-routing suggestion:

| Canonical fitness | Planner route |
|---|---|
| `NOT_FIT` | `BLOCK_ACCEPTANCE_PENDING_NEW_EVIDENCE_OR_CONTEXT` |
| `REVIEW_REQUIRED` | `HUMAN_REVALIDATION_REQUIRED` |
| `READY_FOR_AUTHORITY_CHECK` | `ELIGIBLE_FOR_SEPARATE_ACCEPTANCE_REVIEW` |

These routes are advisory. In particular:

```text
READY_FOR_AUTHORITY_CHECK != accepted memory
NOT_FIT != authority to close/delete
REVIEW_REQUIRED != automatic rejection
```

## Authority boundary

Every plan is fixed to:

```text
mode = REVIEW_ADVISORY_ONLY
authority_granted = false
merge_authority = false
close_authority = false
acceptance_authority = false
execution_authority = false
policy_mutation_authority = false
```

The planner cannot merge, close, accept, reject, delete, rewrite, or execute anything.

## Synthetic conformance fixture

`benchmarks/experimental/memory-proposal-queue-planner-v0.2.synthetic.json` is deliberately marked:

```text
synthetic = true
```

It exercises six distinct Memory Pack identities across three explicit lineage roots and all three canonical information-fitness postures.

The synthetic fixture is mechanical conformance evidence only. It is not a claim about the current 36-proposal production queue.

## Fail-closed cases

The planner rejects:

- incomplete record coverage;
- duplicate proposal/source/merge/pack identities;
- missing lineage or gate evidence refs;
- malformed source-audit/current-main bindings;
- invalid enum values;
- caller-claimed fitness that contradicts canonical CML composition.

## Relationship to Graph–Field Dynamics

Graph–Field Dynamics may identify `cml-memory-proposal-pressure` as an orientation hotspot.

CML remains the source of truth for:

- Memory Pack identity;
- applicability;
- information quality;
- information fitness;
- review/acceptance policy.

Therefore the separation remains:

> Field proposes. Graph constrains. Authority permits. Evidence verifies.

For this workflow specifically:

```text
GFD orientation
  -> CML queue audit
  -> CML per-pack trust gates
  -> planner review grouping
  -> separate human acceptance review
```

No step before the final authority process can accept a Memory Pack.
