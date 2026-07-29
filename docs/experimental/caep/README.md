# Portable Causal Action Episode (CAEP) — experimental v0.1.0

CAEP is an experimental execution-record profile for Causal Memory Layer (CML) and MCP workflows.

It represents:

`observable state → intent → authorization → decision → exact tool dispatch → outcome → independent verification → recovery`

CAEP complements ordinary logs and provenance traces by checking whether a tool action was an authorized, observable, digest-bound, and verifiable state transition.

## Files

- `caep.schema.json` — JSON Schema Draft 2020-12.
- `caep.example.json` — independently verified successful external write.
- `caep.diverged.example.json` — duplicate-payment divergence and containment.
- `caep.recovered.example.json` — compensation record whose parent is the digest-bound divergence record.
- `caep.absurdity-trajectory.json` — multidimensional causal and temporal failure-injection scenario.
- `ABSURDITY_TRAJECTORY.md` — graph, orientation center, candidate paths, and guardrails.
- `validate_caep.py` — schema, semantic, digest, duplicate-key, and parent-binding validation.
- `test_validate_caep.py` — mutation and tamper tests.

## Validate

```bash
python -m pip install jsonschema

python docs/experimental/caep/validate_caep.py \
  docs/experimental/caep/caep.example.json

python docs/experimental/caep/validate_caep.py \
  docs/experimental/caep/caep.diverged.example.json

python docs/experimental/caep/validate_caep.py \
  docs/experimental/caep/caep.recovered.example.json \
  --parent docs/experimental/caep/caep.diverged.example.json

python -m unittest \
  docs/experimental/caep/test_validate_caep.py
```

Expected result for each record is `VALID`; the tests should pass.

## Integrity model

`caep-json-v1` canonicalizes a record as UTF-8 JSON with object keys sorted, no insignificant whitespace, non-ASCII text preserved, and non-finite numbers rejected.

The SHA-256 record digest covers every field except:

- `integrity.record_digest`;
- `integrity.signature`.

Every ID in `causal_parent_ids` must have a matching `integrity.parent_digests` entry. Validation of a non-root record requires each parent file through `--parent`; the validator recomputes both the parent's own digest and the child binding.

## Core invariants

1. Intent, authorization, decision, dispatch, outcome, and verification remain separate.
2. Every declared postcondition is covered by a verification check.
3. Checks cannot target undeclared postconditions.
4. Independent verification requires an identified verifier distinct from the executor.
5. `recovered` requires `recovery.status=recovered` and `verification.verdict=verified`.
6. Write and destructive actions require explicit authorization and recovery metadata.
7. `valid_time` and `recorded_time` are separate offset-aware timestamps.
8. Tool success is not accepted as business success until postconditions pass.
9. History is preserved through digest-bound causal parents rather than rewritten.
10. Malformed or duplicate-key JSON fails closed without a traceback.
11. Decision records contain reason codes and evidence references, not private chain-of-thought.
12. Recovery follows the smallest justified reversible action toward a declared orientation center.

## Relationship to CML

CML checks causal lineage such as missing parents, ambiguous roots, and broken responsibility paths. CAEP provides a portable envelope carrying those relationships across multi-server MCP workflows while recording postconditions and recovery.

The absurdity trajectory shows how stale observations, late-recorded parallel events, and individually correct tools can create a globally invalid state. The recovery episode points directly to the digest-bound divergence episode, preserving the reason payment B was cancelled.

This prototype is intentionally non-normative. `org.causal-memory-layer.caep` and the `$id` URN are working identifiers, not official MCP registrations or security certification.

Disclosure: prepared with AI assistance under human direction and review.
