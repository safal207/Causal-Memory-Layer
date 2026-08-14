# Focus–Field Recovery Protocol v0.2

Status: **experimental / non-normative**

## Core hypothesis

Long-running agents often recover context by replaying or traversing prior history. Focus–Field Recovery tests a different primitive:

1. **Value anchor** — preserve what matters before widening search.
2. **Focus** — execute on the explicit causal graph.
3. **Saturation / interruption** — detect when local continuation is no longer reliable or efficient.
4. **Observe / defocus** — enter a non-action state instead of forcing the next transition.
5. **Field retrieval** — evaluate a bounded set of possible recovery anchors.
6. **Select** — choose the best supported continuation candidate.
7. **Re-anchor** — recover context from that prior graph state without replaying every intermediate edge.
8. **Verify current applicability** — distinguish historical usefulness from a trusted current continuation point.

```text
VALUE
  |
  v
FOCUS / GRAPH
  |
  | saturation, interruption, drift
  v
OBSERVE / DEFOCUS
  |
  v
FIELD OF POSSIBLE ANCHORS
  |
  | deterministic ranking
  v
SELECT
  |
  +--> historical/stale --> REANCHORED_EXPLORATORY
  |                         trusted_continuation=false
  |
  +--> applicability MATCH
       + information READY
       + evidence refs
            |
            v
         REANCHORED
         trusted_continuation=true
```

The "field" is an engineering abstraction, not a claim about a physical field: it is a bounded set of candidate continuation states that can be evaluated without sequential graph rewind.

## v0.2 correction: historical evidence is not current trust

The original v0.1 branch was created from CML main `1635804f127b7840dca0cd2679c0f001552b7b10`. It represented verification with a local boolean:

```text
verified: true/false
+ evidence_refs
```

CML main later added stronger canonical contracts for:

- current-state memory applicability;
- source and lineage integrity;
- repository/commit/environment binding;
- information quality;
- exact evidence binding to evaluated item, source record, and accepted state token.

Therefore a historical anchor can no longer become a trusted continuation merely because an old branch marked it `verified=true`.

v0.2 removes that boolean. A trusted continuation now requires the current canonical gates:

```text
anchor.evidence_refs != empty
AND MemoryApplicability.may_influence_action == true
AND InformationQuality.ready_for_authority_check == true
```

In current CML this means applicability is exactly `MATCH` and information readiness is exactly `READY`.

An anchor with `REVALIDATE`, `DRIFT`, `ORPHAN`, `UNRESOLVABLE`, `REJECT`, `REVIEW`, or `EXCLUDE` may still be useful as historical context when the caller permits exploratory recovery, but it cannot silently become trusted current state.

## Why this differs from a plain loop

A loop governs **repetition**: act, observe feedback, decide whether to continue, and repeat.

Focus–Field Recovery governs **geometry of context recovery**: when the current trajectory becomes a poor continuation point, the system can temporarily stop local traversal, inspect multiple candidate anchors, and resume context from the strongest one.

A conventional recovery path may behave like:

```text
A -> B -> C -> D -> E -> F -> G
                         <- <- <-  replay / rewind
```

Field-mediated recovery permits:

```text
G
|
v
FIELD{value, concepts, goals, causes, phase, time, evidence}
        |
        +------> D or E
                   |
                   v
             current-state gates
               /         \
       exploratory      trusted
```

The protocol does **not** claim this is always superior. The claim is falsifiable: on suitable long-horizon workloads it may reduce recovery work while preserving or improving correctness.

## Translation of the human inspirations

Some human metaphors motivated the design, but the implementation uses testable engineering concepts:

| Human metaphor | Engineering translation |
|---|---|
| love of the process | explicit value / intent anchor |
| observation | non-action metacognitive state |
| emptiness | preserve option space; do not force a transition |
| space of variants | bounded candidate recovery field |
| choosing a variant | rank and select a continuation anchor |
| returning to self | restore stable intent / identity constraints |
| illuminating the space | widen retrieval only after value anchoring |
| elegant path | minimum sufficient verified continuation |

These mappings are design metaphors, not scientific claims about spiritual or metaphysical mechanisms.

## v0.2 scoring signals

The deterministic ranking signals remain intentionally inspectable.

| Signal | Purpose | Weight |
|---|---|---:|
| concept overlap | semantic continuity | 0.25 |
| value overlap | preserve intent / principles | 0.15 |
| goal overlap | preserve objective | 0.15 |
| causal overlap | preserve why the state matters | 0.15 |
| phase match | resume the correct execution phase | 0.10 |
| temporal proximity | prefer temporally relevant anchors | 0.08 |
| unresolved-work bonus | prefer unfinished causal fronts | 0.04 |
| current evidence readiness | current applicability + quality + evidence refs | 0.08 |

No embeddings, model judge, or external service is required.

## Safety invariants

1. **No forced action.** If no candidate clears the threshold, remain in `defocus`.
2. **Deterministic ties.** Equal scores are ordered by stable anchor ID.
3. **Current-state verification gating.** `require_verified=true` admits only anchors passing current canonical CML applicability + information-quality gates.
4. **Historical usefulness != current trust.** A non-current anchor may be selected only as `reanchored_exploratory` with `trusted_continuation=false`.
5. **Inspectable selection.** Every candidate exposes score components and `verification_ready`.
6. **Evidence is not authority.** `trusted_continuation=true` means memory/evidence readiness only; a separate authority check is still required before action.
7. **History is immutable.** Re-anchoring selects a context point; it does not rewrite causal history.
8. **Value precedes expansion.** Broad retrieval cannot silently replace the active intent anchor.

## FCRP-SELF-006 — Temporal Contract Drift

The first meaningful divergence is not a scoring weight. It is the old branch-local trust abstraction:

```text
old branch:
verified bool
      ↓
trusted recovery candidate

current main:
source + lineage + environment
      ↓
MemoryApplicability
      +
exact evidence binding + bounded semantics
      ↓
InformationQuality
      ↓
current recovery eligibility
```

The refactor point is the Focus–Field eligibility/decision boundary. CML memory core remains authoritative; the experiment adapts to it.

This is the intended repository behavior: when canonical trust semantics become stronger, an older experiment must reconcile with the new parent contract before its old verification evidence can be reused.

## Beauty / cost criterion

After correctness, causal consistency, and verification constraints are satisfied, implementations may optimize for a **minimum sufficient path**:

- fewer replayed tokens;
- fewer revisited graph nodes;
- lower recovery latency;
- lower tool/model cost;
- simpler causal explanation;
- fewer unnecessary transitions.

Efficiency never substitutes for current applicability or evidence integrity.

## Benchmark boundary

The deterministic A/B benchmark continues to compare recovery work, not objective model intelligence. Trusted target anchors in the benchmark are now explicitly bound to current CML gate outputs.

A stronger future benchmark should measure real agent traces, noisy fields, tokens, latency, wrong-anchor rate, post-recovery goal drift, current-state revalidation cost, and the break-even point versus sequential replay.

## Current implementation

- implementation: `cml/experimental/focus_field.py`
- A/B benchmark: `benchmarks/experimental/focus_field_recovery.py`
- regression tests: `tests/test_focus_field.py`
- FCRP case: `benchmarks/experimental/fcrp-self-006.json`
