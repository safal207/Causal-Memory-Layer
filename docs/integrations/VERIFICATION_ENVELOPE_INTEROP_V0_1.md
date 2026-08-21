# Verification Envelope Interoperability v0.1

This contract defines a small executable seam for independently implemented
verification systems.

The goal is not to standardize every proof format. It is to make one narrower
question reproducible by a stranger:

> Can another implementation reproduce what was bound, identify which decision
> occurrence the proof refers to, and determine exactly where the proof stops?

## Core shape

The envelope carries:

```text
occurrence_id
content_commitment
commitment_scope
canonicalization_profile
fresh_through
execution_binding
requires_use_time_revalidation
```

These fields deliberately separate concerns that are easy to collapse:

- `occurrence_id` identifies one decision/authorization occurrence. It is not a
  content hash and does not deduplicate distinct intents that happen to have the
  same arguments.
- `content_commitment` binds the exact canonical bytes of the effective content.
- `commitment_scope` says which top-level fields those bytes cover.
- `fresh_through` states the last boundary at which freshness is actually
  established: `issuance`, `consumption`, or `execution`.
- `execution_binding` states whether execution is actually attested. `external`
  is an honest capability disclosure, not a degraded form of `attested`.
- `requires_use_time_revalidation` is explicit so a valid signature/hash cannot
  silently imply live freshness.

The compact invariant is:

> A verifier must be able to reproduce what was bound, identify which occurrence
> it belongs to, and know exactly where the proof stops.

## Canonicalization profile

CML does not currently depend on an RFC 8785 implementation. v0.1 therefore does
**not** pretend to provide full JCS.

The frozen profile is:

```text
rfc8785-jcs-ascii-integer-subset-v0.1
```

It permits only values for which the dependency-free encoder used here is
byte-compatible with RFC 8785 JCS:

- ASCII object keys and strings;
- integers within the interoperable safe range `[-(2^53-1), 2^53-1]`;
- booleans;
- null;
- arrays;
- objects.

Floats and non-ASCII strings are rejected rather than encoded under a stronger
compatibility claim than this implementation can prove.

This is intentional. The first cross-system test should be a shared byte vector,
not the fact that two repositories happen to list the same canonicalization
library as a dependency.

## Frozen vector

`tests/fixtures/verification_envelope_v0.1.json` freezes one healthy vector.
Its bound content is:

```json
{
  "args": {
    "amount_cents": 5000,
    "currency": "USD",
    "recipient": "merchant-42"
  },
  "tool": "charge_card"
}
```

The expected canonical UTF-8 bytes decode to:

```text
{"args":{"amount_cents":5000,"currency":"USD","recipient":"merchant-42"},"tool":"charge_card"}
```

and their SHA-256 is:

```text
603e6a4e5dcf67b03b2e0221a0d26f1feafd2a8db0f10f71d5becd5c29ef0d4b
```

An independent implementation passes the byte-level seam only if it reproduces
those canonical bytes and that digest from the semantic JSON object, without
using CML code.

## Capability disclosure

The healthy fixture intentionally uses:

```text
fresh_through = consumption
execution_binding = external
requires_use_time_revalidation = true
```

That combination is a valid result.

It proves neither execution nor execution-time freshness. A consumer requiring
those properties must fail closed instead of reading a proof-shaped object as a
stronger guarantee.

The v0.1 negative controls freeze exactly that distinction:

1. argument drift changes the content commitment;
2. occurrence drift fails even when content is identical;
3. `execution_binding=external` cannot satisfy a requirement for execution
   attestation;
4. `fresh_through=consumption` cannot satisfy a requirement for execution-time
   freshness.

## Why occurrence identity is separate

Two independent intents can have identical tool arguments. A content digest is
therefore not an occurrence identifier.

The envelope keeps:

```text
occurrence identity
!=
content identity
```

A verifier can require both:

```text
expected occurrence matches
AND
recomputed content commitment matches
```

This prevents a correctly hashed action from silently standing in for a
separate authorization occurrence.

## Why ordering is not enough

Ordering can establish that one event happened before another. It cannot prove
that the later event is the action authorized by the earlier one.

The content commitment is the binding. Timing/freshness is an additional
constraint, not a substitute for that binding.

## Interoperability bar

A useful cross-system run should publish at least:

```text
producer implementation + commit
consumer implementation + commit
fixture version
canonical bytes reproduced: yes/no
content digest reproduced: yes/no
occurrence binding: pass/fail
freshness requirement: pass/fail + disclosed boundary
execution binding: pass/fail + disclosed boundary
```

A failed row is useful evidence. This is a conformance measurement, not a
certification.

## Non-claims

v0.1 does not claim full RFC 8785 support. It does not define a signature format,
key distribution, clock authority, execution attestation mechanism, or transport.
It does not turn `execution_binding=external` into execution evidence.

It establishes one small shared surface that can be independently recomputed.
The next step is to run the frozen vector through a second implementation and
compare bytes, digest, occurrence semantics, and capability disclosure.
