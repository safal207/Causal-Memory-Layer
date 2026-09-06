# Memory Source Reconciliation v0.1

A populated `source` field is not proof that a memory can be checked again.
This contract separates declared provenance from provenance that is actually
re-fetchable and enumerable.

## Core distinction

```text
source field present
    != locator present
    != source re-fetchable
    != source deterministically re-verified
    != source namespace enumerable
```

A system can therefore report high declared source coverage while having almost
no ability to detect staleness or missed deletions.

## Why source-side enumeration matters

Per-record re-fetch can repair a source when that record is touched again. A
source deleted upstream is different: after the deletion event is missed,
nothing in the index necessarily mentions it again.

The deletion-detection invariant is therefore source-side:

```text
for every completely enumerable source namespace:

IndexedSourceIds ⊆ CurrentSourceIds
```

Any member of `IndexedSourceIds - CurrentSourceIds` is an orphaned index source.
The reverse difference, `CurrentSourceIds - IndexedSourceIds`, is reported as an
index coverage gap.

Partial enumeration is never converted into a clean zero. The namespace remains
explicitly incomplete and cannot support exact deletion claims.

## Coverage metrics

The implementation reports these separately:

- `source_field_coverage` — records with any declared source label;
- `locator_coverage` — records with an origin locator;
- `refetchable_coverage` — records whose origin adapter says can be revisited;
- `refetch_verification_coverage` — records whose origin was deterministically
  decided by re-fetch (including a confirmed deletion) or digest comparison;
- `source_enumeration_coverage` — records carrying a stable source identifier in
  a namespace whose current source set was completely enumerated.

None of these metrics is inferred from schema presence alone. They are computed
from measured adapter observations supplied to the reconciliation core.

## Frozen fixture

`tests/fixtures/memory_source_reconciliation_v0.1.json` includes six cases:

1. a writer label that looks like provenance but cannot be re-fetched;
2. a re-fetchable source whose namespace cannot be completely enumerated;
3. a clean complete source/index match;
4. a deleted source that remains resident in the index;
5. a current source that has no indexed representation;
6. 100% declared source coverage with only one third actually verifiable and
   enumerable.

The companion tests also prove that incomplete enumeration cannot claim a
source deletion and that duplicate inventory authorities fail closed.

## Composition

This layer is additive and does not introduce a new applicability verdict.
It complements `MEMORY_APPLICABILITY_V0_1.md` and
`MEMORY_LINEAGE_V0_1.md`:

```text
retrieval reliability
    -> source-side reconciliation / measured provenance coverage
    -> source integrity
    -> lineage / supersession
    -> current-state applicability
    -> authority guard
    -> action
    -> evidence
```

The intended operational rule is simple: **presence is not provenance, and
re-fetchability is not deletion detection unless the authoritative source can
also be enumerated.**
