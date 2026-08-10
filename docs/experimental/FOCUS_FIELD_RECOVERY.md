# Focus–Field Recovery Protocol v0.1

Status: **experimental / non-normative**

## Core hypothesis

Long-running agents often recover context by replaying or traversing prior history. Focus–Field Recovery tests a different primitive:

1. **Value anchor** — preserve what matters before widening search.
2. **Focus** — execute on the explicit causal graph.
3. **Saturation / interruption** — detect when local continuation is no longer reliable or efficient.
4. **Observe / defocus** — enter a non-action state instead of forcing the next transition.
5. **Field retrieval** — evaluate a bounded set of possible recovery anchors.
6. **Select** — choose the best supported continuation candidate.
7. **Re-anchor** — resume from that prior graph state without replaying every intermediate edge.
8. **Verify** — require evidence and invariants before trusted continuation.

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
SELECT -> RE-ANCHOR -> VERIFY
                         |
                         v
                    FOCUS / GRAPH
```

The "field" is an engineering abstraction, not a claim about a physical field: it is a bounded set of candidate continuation states that can be evaluated without sequential graph rewind.

## Why this differs from a plain loop

A loop governs **repetition**: act, observe feedback, decide whether to continue, and repeat.

Focus–Field Recovery governs **geometry of context recovery**: when the current trajectory becomes a poor continuation point, the system can temporarily stop local traversal, inspect multiple candidate anchors, and resume from the strongest one.

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
        +------> D or E -> verified continuation
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

## v0.1 scoring signals

The first scorer is deliberately deterministic and inspectable.

| Signal | Purpose | Weight |
|---|---|---:|
| concept overlap | semantic continuity | 0.25 |
| value overlap | preserve intent / principles | 0.15 |
| goal overlap | preserve objective | 0.15 |
| causal overlap | preserve why the state matters | 0.15 |
| phase match | resume the correct execution phase | 0.10 |
| temporal proximity | prefer temporally relevant anchors | 0.08 |
| unresolved-work bonus | prefer unfinished causal fronts | 0.04 |
| evidence quality | prefer verified evidenced anchors | 0.08 |

No embeddings, model judge, or external service is required in v0.1.

## Safety invariants

1. **No forced action.** If no candidate clears the threshold, remain in `defocus`.
2. **Deterministic ties.** Equal scores are ordered by stable anchor ID.
3. **Verification gating.** A caller may restrict recovery to verified anchors only.
4. **Inspectable selection.** Every candidate exposes score components.
5. **Evidence is not authority.** Evidence can improve confidence but cannot grant action permission by itself.
6. **History is immutable.** Re-anchoring selects a continuation point; it does not rewrite causal history.
7. **Value precedes expansion.** Broad retrieval cannot silently replace the active intent anchor.

## Beauty / cost criterion

After correctness, causal consistency, and verification constraints are satisfied, implementations may optimize for a **minimum sufficient path**:

- fewer replayed tokens;
- fewer revisited graph nodes;
- lower recovery latency;
- lower tool/model cost;
- simpler causal explanation;
- fewer unnecessary transitions.

"Beauty" is therefore operationalized as efficient, legible, sufficient continuation — never as a substitute for correctness.

## First benchmark

Compare the same interrupted long-horizon tasks under two strategies.

### Baseline: sequential/history recovery

Replay or traverse prior task history until enough context is reconstructed.

### Experimental: field-mediated recovery

Enter defocus, build a bounded field, score anchors, re-anchor, verify, and resume.

Measure:

- recovery success rate;
- downstream task completion / verification rate;
- wrong-anchor rate;
- goal drift;
- causal-consistency violations;
- tokens consumed during recovery;
- recovery latency;
- history or graph nodes revisited;
- verification/evidence retention;
- graph rewind steps avoided.

## Falsification criteria

The hypothesis is unsupported for a workload when field recovery materially increases wrong-anchor or goal-drift rates, loses causal/verification context, or consumes comparable or greater recovery resources without improving downstream success.

## Current implementation

Experimental implementation: `cml/experimental/focus_field.py`.

Regression coverage: `tests/test_focus_field.py`.
