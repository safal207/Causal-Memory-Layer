# Causal Equilibrium Point (experimental)

## Purpose

A causal graph can be structurally valid and still be incomplete, one-sided, or dependent on unresolved memory. The **Causal Equilibrium Point** is a read-only audit checkpoint that asks whether the material causal context for an action is sufficiently resolved to describe the checkpoint as:

- `BALANCED`
- `UNSTABLE`
- `INDETERMINATE`

This is not a policy engine and does not decide whether an action is correct.

## Why this layer exists

CML already checks structural properties such as parent resolution and acyclicity. Those checks answer:

> Is the causal graph structurally sound?

The equilibrium layer asks a different question:

> Is the recorded causal context complete enough to show supporting evidence, counterevidence, memory influence, unresolved references, and preserved provenance?

A graph may pass structural validation while still omitting counterevidence or hiding that recalled memory influenced the action.

## Experimental contract

```python
CausalEquilibriumSnapshot(
    action_ref="action-1",
    supporting_refs=("support-1",),
    counter_refs=("counter-1",),
    recalled_memory_refs=("memory-1",),
    unresolved_refs=(),
    consolidation_source_refs=("support-1", "counter-1"),
    consolidation_preserved_refs=("support-1", "counter-1"),
    require_counterevidence=True,
)
```

The evaluator also receives `known_refs`, representing causal records and memories available to the audit process.

## Deterministic states

### `BALANCED`

No equilibrium findings are present. Material references resolve, required counterevidence exists, recalled memories resolve, and declared consolidation provenance is preserved.

### `UNSTABLE`

At least one `FAIL` finding exists. This currently covers unresolved memory influence or provenance loss during memory consolidation.

### `INDETERMINATE`

No `FAIL` finding exists, but at least one `WARN` finding exists. This covers missing required counterevidence, unresolved material references, explicitly unresolved references, or an empty checkpoint.

## Findings

| Code | Severity | Meaning |
|---|---|---|
| `CML-EQ-01-MISSING_COUNTEREVIDENCE` | `WARN` | Counterevidence was required but not recorded. |
| `CML-EQ-02-UNRESOLVED_MEMORY_INFLUENCE` | `FAIL` | A recalled memory influencing the action cannot be resolved. |
| `CML-EQ-03-CONSOLIDATION_IMBALANCE` | `FAIL` | Memory consolidation lost declared provenance references. |
| `CML-EQ-04-INDETERMINATE_STATE` | `WARN` | The checkpoint lacks enough resolved material for a balanced state. |

## Canonical findings order

For portable conformance results, findings are emitted using this exact ascending key:

```text
(code, severity_rank, refs_lexicographic, message)
```

Severity ranks are explicit:

```text
FAIL = 0
WARN = 1
```

References inside each finding are normalized lexicographically before sorting and output. The ordering rule is part of the experimental v1 contract rather than an implementation detail.

## Versioned conformance fixtures

The v1 fixture set turns the experimental semantics into a portable contract:

- [`benchmarks/equilibrium/v1/fixtures.json`](../../benchmarks/equilibrium/v1/fixtures.json)
- [`benchmarks/equilibrium/README.md`](../../benchmarks/equilibrium/README.md)
- [`tests/test_equilibrium_fixtures.py`](../../tests/test_equilibrium_fixtures.py)

The set covers all three states, every current finding path, consolidation provenance, recalled-memory influence, an empty checkpoint, and multiple simultaneous findings. Tests also reverse the set-like input collections to verify that output does not depend on input order.

A matching implementation demonstrates reproduction of this published experimental contract. It does not establish decision correctness.

## Relationship to episodic memory

Within one session, `parent_action_ref` records direct causal lineage. Across sessions, `recalled_memory_refs` records memory influence. The equilibrium checkpoint does not merge these concepts; it audits whether both layers remain explicit and resolvable.

When memories are summarized, clustered, or deduplicated, `consolidation_source_refs` and `consolidation_preserved_refs` make provenance loss visible.

## Non-claims

The equilibrium evaluator does not:

- judge truth or decision quality;
- require numerical symmetry between supporting and counter evidence;
- assign moral weight to evidence;
- block actions;
- enforce policy;
- prove safety, compliance, or fairness;
- replace signatures, external anchors, or human review.

`BALANCED` means the declared audit conditions are satisfied. It does not mean the action is objectively correct.

## Implementation

- Module: [`cml/experimental/equilibrium.py`](../../cml/experimental/equilibrium.py)
- Unit tests: [`tests/test_equilibrium.py`](../../tests/test_equilibrium.py)
- Conformance tests: [`tests/test_equilibrium_fixtures.py`](../../tests/test_equilibrium_fixtures.py)
- Example: [`examples/causal_equilibrium_point.py`](../../examples/causal_equilibrium_point.py)

The API remains experimental and non-normative while the concept is evaluated against agent-memory and multi-session trace use cases.
