# ASTRA — Experimental Causal Genome for CML

Status: **experimental / non-normative**

ASTRA is a research topology for representing how a causal belief is activated, supported, changed, and structurally invalidated over time.

The flower / helix / DNA vocabulary is an engineering analogy only. ASTRA does not claim that software memory is biological DNA.

## Why add ASTRA to CML?

CML already audits whether an action has valid causal lineage. ASTRA explores a complementary question:

> How can a causal-memory unit preserve not only what is believed, but also the context in which it may activate, the evidence attached to it, the mutations that changed it, and the defects that make its structure unsafe to trust?

The first version is intentionally small and deterministic.

## v0.1 primitives

### `AstraGene`

One inspectable causal-memory unit. It may carry:

- claim;
- context tags;
- activation conditions;
- causal parents;
- intent, action, expected effect, and observed outcome;
- evidence references;
- counterfactuals;
- invariant references;
- reasoning phase;
- provenance and confidence;
- mutation ancestry.

### Activation context

A stored gene does not automatically become active memory.

`ActivationContext` has required and excluded tags. A gene is eligible only when the current runtime context satisfies those gates.

This gives CML a minimal analogue of context-sensitive expression:

```text
stored knowledge != active knowledge
```

Example:

```text
claim: retry is safe
required: idempotent
excluded: revoked
```

The claim can remain stored while being inactive for a non-idempotent or revoked context.

### Mutation genealogy

ASTRA never overwrites the old belief when a causal model changes. A child gene points to the exact parent and records a mutation kind:

```text
belief-v1: A -> B
    |
    | refinement: condition C discovered
    v
belief-v2: A + C -> B
```

This preserves an inspectable history of why the current causal model differs from an earlier one.

Supported mutation kinds in v0.1:

- `refinement`
- `contradiction`
- `context_split`
- `evidence_update`
- `supersession`

### Provenance is not collapsed into truth

ASTRA keeps distinct provenance labels:

- `observed`
- `user_provided`
- `verified`
- `inferred`
- `reconstructed`
- `simulated`

A reconstructed or simulated memory must not silently become a historical fact.

Even `verified` is not trusted by the v0.1 helper unless an evidence reference remains attached.

```text
verified + detached evidence != trusted claim
```

### Complementary causal pairs

The helix analogy becomes useful when paired surfaces can check one another:

```text
claim           <-> evidence
action          <-> outcome
expected effect <-> observed effect
cause reference <-> existing causal gene
```

A broken pair is surfaced as a defect rather than guessed away.

### Topological defects

`AstraGenome.detect_defects()` currently exposes:

- `missing_evidence`
- `unverified_action`
- `intent_effect_divergence`
- `dangling_cause`
- `dangling_parent`
- `genealogy_cycle`

The detector is deliberately fail-visible. It reports a broken structure but does not mutate the genome or reconstruct missing history.

## Shape of the model

Conceptually:

```text
          evidence
             |
context -- ASTRA GENE -- action
             |
           outcome
             |
          mutation
             |
        next ASTRA gene
```

A sequence of mutations forms an `AstraGenome`:

```text
AstraGene_1 -> AstraGene_2 -> AstraGene_3 -> ...
```

Future versions may layer this sequence into a helix where separate surfaces represent reality, meaning, intent, evidence, and counterfactual alternatives. v0.1 does not encode 3-D geometry because geometry without deterministic semantics would be decorative rather than useful.

## Trust boundary

ASTRA is experimental. It must not be treated as:

- merge authority;
- runtime authorization;
- proof that a causal relation is scientifically true;
- automatic repair authority;
- a replacement for CML's stable audit findings.

Its role is to make causal-memory evolution inspectable and testable.

## v0.1 acceptance properties

The initial implementation is expected to preserve these properties:

1. Context activation is deterministic and case-normalized.
2. Excluded context wins over required-context satisfaction.
3. Mutation creates a child and preserves the parent unchanged.
4. Mutation lineage is inspectable root-to-child.
5. Verified provenance without attached evidence is not trusted.
6. Missing evidence, dangling causes, incomplete actions, intent/effect divergence, and genealogy cycles remain visible defects.
7. Defect detection never silently repairs history.

## Next research increments

A sensible sequence after v0.1 is:

1. **AstraPetal** — typed complementary relationships around one gene.
2. **AstraHelix** — ordered reality/meaning/evidence lanes across time.
3. **AstraField** — integrate ASTRA activation with the existing experimental Focus–Field recovery protocol.
4. **Resonance** — detect independently supported recurring causal motifs.
5. **Bloom** — propose higher-order concepts while preserving the supporting genes.
6. **Repair witness** — represent a reconstructed candidate separately from historical truth and require verification before promotion.

The central design rule stays the same:

> evolution may create a new belief, but it must not erase how that belief came to exist.
