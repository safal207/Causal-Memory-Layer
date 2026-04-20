# Multi-hop QA Causal Mismatch (A→B vs A→C)

Input: `examples/multihop_qa_mismatch_log.jsonl`

## Summary
- OK: 6
- WARN: 0
- FAIL: 1

## Findings

### FAIL — CML-AUDIT-MISSING_REQUIRED_EDGE
- Record: `h2_B`
- Reason: required edge `A→B` has `parent_cause = null` and `permitted_by = unobserved_parent`
- The B edge was never used as a `parent_cause` for any downstream step

Reconstructed context:
- Hop 1: `h1` resolves entity_A correctly (parent_cause: q1)
- Hop 2 (required): `h2_B` — edge A→B bypassed (parent_cause: null) ← gap here
- Hop 2 (actual): `h2_C` — edge A→C used instead (parent_cause: h1)
- Hops 3–5: chain continues cleanly through C→D→E→Z (causally valid relative to h2_C)

## Interpretation

The answer was produced via a causally complete chain — but through the wrong path.

The surface reasoning trace (`A → C → D → E → Z`) is internally consistent and
has no gaps. The audit flag is that the ground-truth edge `A→B` never appears as
a `parent_cause` in any downstream record. The required intermediate fact was
silently substituted with a more plausible alternative, and the substitution is
only visible in the causal record, not in the final output.

This is the core failure class CML is designed to surface: a functionally valid
answer that is causally disconnected from the required authorization path.
