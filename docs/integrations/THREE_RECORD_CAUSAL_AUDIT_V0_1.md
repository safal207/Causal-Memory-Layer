# Three-Record Causal Audit v0.1

**Status:** Draft interoperability profile  
**Issue:** [CML #163](https://github.com/safal207/Causal-Memory-Layer/issues/163)  
**Canonical profile:** [Liminal #108](https://github.com/safal207/Liminal/issues/108)

## Purpose

This profile validates causal lineage across three independently issued records:

1. `authorization_record`;
2. `observation_record`;
3. `response_integrity_record`.

CML answers whether the supplied records belong to one causally coherent
transition. It does not issue authority, execute actions, or determine whether a
model claim is semantically true.

## Files

- Auditor: [`cml/three_record_audit.py`](../../cml/three_record_audit.py)
- Primary fixtures: [`tests/fixtures/three_record_causal_audit_v0.1.json`](../../tests/fixtures/three_record_causal_audit_v0.1.json)
- Broken-edge fixtures: [`tests/fixtures/three_record_causal_audit_edges_v0.1.json`](../../tests/fixtures/three_record_causal_audit_edges_v0.1.json)
- Main tests: [`tests/test_three_record_causal_audit.py`](../../tests/test_three_record_causal_audit.py)
- Parent-reference tests: [`tests/test_three_record_causal_parent_refs.py`](../../tests/test_three_record_causal_parent_refs.py)

Run:

```bash
pytest tests/test_three_record_causal_audit.py tests/test_three_record_causal_parent_refs.py -q
```

## Portable canonical wrappers

Every supplied record uses:

```json
{
  "record": {},
  "record_ref": "sha256:..."
}
```

The reference is recomputed from deterministic compact JSON bytes. Canonical
values must be JSON-only, finite, and composed of Unicode scalar strings;
unpaired surrogate code points and non-JSON objects are rejected with
`ThreeRecordAuditError` rather than leaking encoder-specific exceptions.

A reference mismatch is emitted as a causal finding rather than silently
trusted.

This v0.1 profile intentionally defines one canonical wrapper and field schema.
ProofPath-, Pythia-, ibex-, LTP-, provider-, or framework-specific records must
be normalized by an explicit adapter before calling the auditor. Adapter
selection and source-format interpretation are outside this core contract; the
auditor never guesses aliases or inferred field mappings.

## Required causal edges

Authorization to observation:

```text
observation.authorization_ref -> authorization.record_ref
observation.transition_id == authorization.transition_id
observation.subject_id == authorization.subject_id
observation.action_identity_digest == authorization.action_identity_digest
observation.binding_digest == authorization.binding_digest
```

All identity and binding fields above must be non-empty strings on both sides.
Missing, empty, or whitespace-only values cannot establish a join merely because
they compare equal.

Observation to response integrity:

```text
response_integrity.authorization_ref -> authorization.record_ref
response_integrity.transition_id == authorization.transition_id
response_integrity.subject_id == authorization.subject_id
response_integrity.observation_refs -> supplied observation.record_ref values
claim.observation_refs -> supplied observation.record_ref values
```

An authorization record must either identify at least one non-empty causal
parent reference or explicitly mark itself with `causal_root=true`. Empty and
whitespace-only entries in `causal_parent_refs` provide no ancestry and cannot
make an otherwise ambiguous root valid. Valid external parent references remain
supported even when blank noise is also present.

## Finding codes

| Code | Broken edge or condition |
|---|---|
| `CML-TTR-R1-MISSING_AUTHORIZATION_PARENT` | Observation or integrity record does not point to the supplied authorization record. |
| `CML-TTR-R2-OBSERVATION_ACTION_BINDING_MISMATCH` | Observation action or argument binding is absent, empty, or differs from authorization. |
| `CML-TTR-R3-OBSERVATION_WITHOUT_EXECUTABLE_AUTHORITY` | An executed observation descends from denied, pending, expired, consumed, or otherwise non-executable authority. |
| `CML-TTR-R4-CLAIM_UNRELATED_OBSERVATION` | Integrity record or claim references an observation outside the supplied transition. |
| `CML-TTR-R5-STALE_OR_CONSUMED_AUTHORITY_AS_LIVE` | Expired, consumed, or revalidation-required authority is reused for live execution. |
| `CML-TTR-R6-CROSS_SUBJECT_OR_TRANSITION_JOIN` | Required subject or transition identity is absent, empty, or differs across joined records. |
| `CML-TTR-R7-SUPPORTED_CLAIM_NO_LINEAGE` | A `SUPPORTED` claim lacks complete observation ancestry. |
| `CML-TTR-R8-CAUSAL_CYCLE_OR_AMBIGUOUS_ROOT` | The record graph contains a cycle or the authorization has neither a non-empty causal parent nor an explicit root marker. |
| `CML-TTR-R9-RECORD_REFERENCE_MISMATCH` | A wrapper reference does not match the deterministic record digest. |

Every finding includes:

```text
edge
record_ids
message
optional context
```

The same stable code may legitimately appear on distinct broken edges. Exact
finding identity is the tuple `(code, edge, record_ids)`; identical tuples are
deduplicated while distinct edge failures remain visible.

## Independent dimensions

The output preserves four dimensions:

```text
authority
execution
response_integrity
causal_validity
```

A valid causal chain may still contain a contradicted model response:

```text
VALID + OBSERVED_EXECUTED + FAILED + VALID
```

Likewise, an integrity verdict of `VERIFIED` cannot repair a broken action
binding or cross-transition substitution:

```text
VALID + OBSERVED_EXECUTED + VERIFIED + INVALID
```

## Fixture and reliability coverage

The deterministic corpus covers:

- valid authorization → observation → supported claim;
- valid authorization → observation → contradicted claim;
- denied authorization → no observation → false execution claim;
- expired authorization → observed runtime block → honest response;
- observation action/binding mismatch;
- missing, empty, and whitespace-only identity/binding evidence;
- blank-only causal-parent ancestry and valid external parents with blank noise;
- cross-subject and cross-transition substitution;
- claim referencing an unrelated observation on multiple distinct edges;
- digest-only redacted evidence;
- broken authorization parent link;
- ambiguous authorization root;
- a real authorization ↔ observation cycle;
- consumed authority reused for execution;
- tampered wrapper reference;
- non-Unicode-scalar canonical input rejection;
- deterministic iterative traversal of lineage deeper than Python's recursion limit.

Cycle detection uses an explicit stack with sorted node and parent iteration, so
its result is deterministic and does not depend on Python recursion depth.

## Redacted evidence

CML can validate digest-only records. The auditor does not require raw arguments,
credentials, tool output, payment payloads, or other sensitive material when the
portable identity and binding digests are available.

Digest-only lineage proves record relationships, not the hidden payload's
semantic correctness.

## Boundary

This profile does not:

- issue or repair authorization;
- infer or normalize third-party record schemas;
- choose a ProofPath/Pythia/ibex/LTP/provider adapter;
- decide whether tool output is factually correct;
- convert an integrity verdict into causal validity;
- prove signer identity or attestation trust;
- certify production safety or compliance.

## Canonical invariant

> Authority explains why an action could proceed. Observation records what
> happened. Response integrity evaluates what the model claimed. CML verifies
> that those records belong to one causally coherent transition without
> collapsing their independent verdicts.
