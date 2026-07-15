# GuardrailDecisionV1

`GuardrailDecisionV1` is a dependency-free, content-addressed contract for a
pre-tool authorization decision. It answers a narrow question:

> Did the authoritative decision inputs change after the decision was issued?

It does not prove provider independence or authorship. Signatures and external
anchors are optional proof sidecars and must be evaluated separately.

## Authoritative claims

Every v1 decision binds these fields into `decision_id`:

```json
{
  "request_digest": "<sha256>",
  "verdict": "ALLOW | DENY | SUSPEND",
  "reason_code": "<stable reason>",
  "provider_id": "<provider identity>",
  "policy_digest": "<sha256>",
  "authorization_source_digest": "<sha256>",
  "issued_at": "<RFC3339 UTC milliseconds>",
  "expires_at": "<RFC3339 UTC milliseconds>"
}
```

`authorization_source_digest` may identify a declared authorization DAG, a
policy bundle, a ruleset snapshot, or another source that actually determined
the verdict. Changing one graph edge therefore requires a new digest and a new
`decision_id`.

`expires_at` is inside the same preimage. A provider cannot extend a decision's
validity while preserving its identity.

## Identity derivation

The preimage is compact sorted UTF-8 JSON:

```json
{
  "claims": { "...": "all authoritative claims" },
  "schema_version": "cml-guardrail-decision-v1"
}
```

Derivation:

```text
decision_id = lowercase_hex(SHA-256(canonical_preimage_utf8))
```

All strings must consist only of Unicode scalar values. Unpaired UTF-16
surrogates are rejected before canonicalization so implementations cannot
disagree about UTF-8 encoding behavior.

For the baseline vector in
`tests/vectors/guardrail_decision_v1/decision-v1-valid.json`:

```text
decision_id = 0152b2fdd53a315e4a2ea6c48cd79f9e076675354537e0efb5fad9f40295fe09
```

## Strict parsing

The loader rejects:

- duplicate JSON keys at any object level;
- unknown top-level fields;
- unknown or missing claim fields;
- non-lowercase or non-64-character digests;
- unsupported verdicts;
- timestamps without exact UTC millisecond precision;
- `expires_at <= issued_at`;
- strings or object keys containing unpaired surrogate code points;
- non-JSON proof values.

This prevents a provider from placing a semantic extension such as
`mutable_expiry_extension` beside the bound claims.

## Verification outcomes

The verifier recomputes the ID and evaluates time validity:

| Finding | Meaning |
| --- | --- |
| `CML-GUARDRAIL-DECISION-ID-MISMATCH` | Claims do not match the issued ID |
| `CML-GUARDRAIL-DECISION-NOT-YET-VALID` | Verification time is before `issued_at` |
| `CML-GUARDRAIL-DECISION-EXPIRED` | Verification time is at or after `expires_at` |

A verifier may report more than one finding. Findings are deterministic and
sorted by code.

## Proof sidecar and equality

An optional `proof` JSON object can carry a signature, external anchor, witness,
or transparency-log reference. It is recursively frozen by the Python
implementation and is not included in `decision_id`.

That separation is intentional:

- `decision_id` proves deterministic content identity;
- proof mechanisms establish authorship, tamper evidence, or independence.

Ordinary Python value equality includes the proof sidecar, so proof-free and
proof-bearing evidence objects are not interchangeable. `GuardrailDecisionV1`
is intentionally unhashable to prevent sets or caches from collapsing those
objects. Call `same_authoritative_identity()` when the comparison should ignore
proof and compare only the bound decision identity.

## Mutation vectors

The repository includes fixed vectors for:

- a valid baseline;
- an extended expiry retaining the old ID;
- a changed policy digest retaining the old ID;
- a changed authorization-source digest retaining the old ID.

Each vector contains the canonical preimage, recomputed ID, and expected
finding codes so another implementation can reproduce the result without
trusting this library.

## Example

```python
from datetime import datetime, timezone

from cml.integrations.guardrail_decision import (
    issue_guardrail_decision,
    verify_guardrail_decision,
)

issued = issue_guardrail_decision(
    request_digest="11" * 32,
    verdict="ALLOW",
    reason_code="POLICY-ALLOW",
    provider_id="declared-dag-provider",
    policy_digest="22" * 32,
    authorization_source_digest="33" * 32,
    issued_at="2026-07-15T12:00:00.000Z",
    expires_at="2026-07-15T12:05:00.000Z",
)

result = verify_guardrail_decision(
    issued,
    now=datetime(2026, 7, 15, 12, 1, tzinfo=timezone.utc),
)
assert result.passed()
```
