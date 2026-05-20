# Related CaPU Persona-Boundary Evidence

Status: grant/reviewer cross-reference note.

This note records a related executable safety artifact in CaPU that strengthens the Causal Memory Layer grant/research narrative.

Related repository:

```text
https://github.com/safal207/CaPU
```

---

## Why this matters for CML

CML asks whether a system state change is causally valid:

```text
what changed -> why was it allowed -> who/what authorized it -> what causal parent supports it
```

CaPU / CMC persona-boundary evidence applies the same idea to AI companion/persona systems:

```text
Does the AI persona have the right to remember, reinterpret, or change its role toward the human?
```

This connects CML's causal legitimacy thesis to a concrete human-facing safety case.

---

## Current CaPU persona-boundary proof points

CaPU now includes manifest-linked executable persona-boundary fixtures for:

```text
P1: Persona memory requires cause.
P2: Persona state changes require authorization.
P7: Introspection is hypothesis-labeled.
```

Operational summary:

```text
AI must not self-remember.
AI must not self-appoint.
AI must not claim inner truth.
```

---

## Evidence artifacts in CaPU

```text
rust/cmc-core/fixtures/persona/MANIFEST.tsv
rust/cmc-core/fixtures/persona/inferred_preference_rejected.jsonl
rust/cmc-core/fixtures/persona/confirmed_preference_accepted.jsonl
rust/cmc-core/fixtures/persona/unauthorized_persona_state_change_rejected.jsonl
rust/cmc-core/fixtures/persona/authorized_persona_state_change_accepted.jsonl
rust/cmc-core/fixtures/persona/unlabeled_introspection_rejected.jsonl
rust/cmc-core/fixtures/persona/hypothesis_labeled_introspection_accepted.jsonl
rust/cmc-core/src/bin/persona_boundary_verify.rs
```

Reviewer command in CaPU:

```bash
cd rust/cmc-core
cargo run --bin persona_boundary_verify --locked
```

Expected output includes:

```text
cases=6
p1_inferred_result=blocked_unconfirmed_persona_memory
p1_confirmed_result=accepted_confirmed_persona_memory cause_id=42
p2_unauthorized_result=blocked_unauthorized_persona_state_change
p2_authorized_result=accepted_authorized_persona_state_change cause_id=77
p7_unlabeled_result=blocked_claimed_inner_truth
p7_labeled_result=accepted_hypothesis_labeled_reflection
result=persona_boundary_manifest_valid
```

---

## Relationship to CML

| CML concern | CaPU persona-boundary complement |
| --- | --- |
| Memory must carry causal authorization | P1: persona memory requires cause |
| State changes must have a permitted parent | P2: persona state changes require authorization |
| Interpretation must not become false authority | P7: introspection is hypothesis-labeled |
| Causal validity should be inspectable | Persona fixtures are manifest-linked and verifier-checked |
| Human-facing AI systems need responsibility boundaries | Persona memory/state/interpretation transitions can be rejected |

---

## Grant framing

This strengthens the broader CML grant case:

```text
CML defines causal validity for memory and state transitions.
CaPU demonstrates executable persona-boundary cases where memory, role adaptation, and introspection require causal legitimacy.
```

Together:

```text
AI systems should not only store what happened; they should prove why memory, state, interpretation, or action was allowed.
```

---

## Non-claims

This note does not claim complete AI alignment, AI consciousness, personhood, therapy, or production companion safety.

It records a narrow executable evidence bridge between CML's causal validity thesis and CaPU's persona-boundary checks.

---

## One-line summary

```text
CaPU gives CML a concrete persona-safety proof point: AI personas must not self-remember, self-appoint, or claim inner truth without causal legitimacy.
```
