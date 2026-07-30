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
- `validate_caep.py` — schema, semantic, digest, duplicate-key, temporal-order, and parent-binding validation.
- `test_validate_caep.py` — mutation, tamper, CLI, and lifecycle tests.
- `interoperability_demo/` — cross-process state, action, verifier, divergence, and recovery demo.
- `mcp_sdk_adapter/` — real official MCP Python SDK sessions over stdio with action and independent verifier servers.
- `trust_console/` — dependency-free browser viewer for human-readable Trust Receipts.

## Open the verified MCP demo

Public Trust Console:

`https://safal207.github.io/Causal-Memory-Layer/trust-console/`

Choose **Load official MCP SDK demo**. The console downloads the CI-generated gzip bundle, verifies its uncompressed SHA-256 against the published provenance manifest, and then presents the happy, divergence, and digest-bound recovery records as human-readable receipts.

The canonical bundle was reproduced byte-for-byte on Python 3.10, 3.11, and 3.12. Its uncompressed SHA-256 is:

`0743a5b18965240e93775682fc4748b32a4e20baeff6e917cdb77e214976589a`

The console is a presentation and browser-side digest-preview layer. The Python validator remains the normative prototype validation path.

## Run through the official MCP Python SDK

From the repository root:

```bash
python -m pip install -e ".[mcp]"
python docs/experimental/caep/mcp_sdk_adapter/run_adapter.py \
  --output /tmp/caep-mcp-sdk-bundle.json
```

This performs real MCP initialization, tool discovery, action calls, independent verification, divergence detection, compensation, and digest-bound CAEP recovery over two separate stdio server processes. Open the generated bundle in Trust Console to inspect the human-readable receipt.

## View a local Trust Receipt

From `docs/experimental/caep/`:

```bash
python -m http.server 8000
```

Open `http://localhost:8000/trust_console/` and choose **Load recovery demo**, upload a generated bundle, or paste a CAEP record.

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

Expected result for each complete record bundle is `VALID`; the tests should pass.

A non-root record is not considered valid unless every ID in `causal_parent_ids` is supplied and its content digest is recomputed successfully. This rule applies to both the Python API and the CLI.

## Integrity model

`caep-json-v1` canonicalizes a record as UTF-8 JSON with object keys sorted, no insignificant whitespace, non-ASCII text preserved, and non-finite numbers rejected.

The SHA-256 record digest covers every field except:

- `integrity.record_digest`;
- `integrity.signature`.

Every ID in `causal_parent_ids` must have a matching `integrity.parent_digests` entry. The validator requires each parent record, recomputes both the parent's own digest and the child binding, and rejects undeclared supplied parents.

Digests provide integrity, not authenticity. The optional signature structure is not exercised by these examples and no trust anchor or signature-verification policy is claimed.

Artifact, request, response, and tool-schema digests in the examples use obvious repeated-hex placeholders. Only CAEP record digests and causal-parent bindings are computed from the example record content.

## Accepted-transition rules

For `status=verified` and `status=recovered`:

- `verification.verdict` must be `verified`;
- `verification.independence` must be `independent`;
- the verifier must be identified and differ from the action executor and decision maker;
- every declared postcondition must be covered by a verification check;
- every verification check must pass;
- accepted write or destructive transitions must declare at least one `critical` postcondition, and every critical postcondition must pass.

`completed` remains a weaker lifecycle claim and does not imply independent business acceptance.

## Temporal scope

The validator enforces offset-aware timestamps and these intra-record relations when the relevant fields are present:

```text
valid_time ≤ recorded_time
dispatch.started_at ≤ dispatch.completed_at
dispatch.completed_at ≤ outcome.observed_at
outcome.observed_at ≤ verification.verified_at
dispatch.started_at ≤ authorization.expires_at
```

Cross-record temporal contradictions, such as a late-recorded parallel event, belong to the trajectory or bundle layer and are demonstrated in `caep.absurdity-trajectory.json`.

## Core invariants

1. Intent, authorization, decision, dispatch, outcome, and verification remain separate.
2. Every declared postcondition is covered by a verification check.
3. Checks cannot target undeclared postconditions.
4. Accepted transitions require an identified independent verifier distinct from the executor and decision maker.
5. `recovered` requires `recovery.status=recovered` and `verification.verdict=verified`.
6. Accepted writes require a passing critical postcondition.
7. Write and destructive actions require explicit authorization and recovery metadata.
8. `valid_time` and `recorded_time` are separate offset-aware timestamps.
9. Tool success is not accepted as business success until postconditions pass.
10. History is preserved through digest-bound causal parents rather than rewritten.
11. Every declared causal parent must be supplied and content-verified.
12. Malformed or duplicate-key JSON fails closed without a traceback.
13. Decision records contain reason codes and evidence references, not private chain-of-thought.
14. Recovery follows the smallest justified reversible action toward a declared orientation center.

## Runtime boundary

CAEP carries postcondition expressions but does not evaluate CEL, JSONPath, Rego, SQL, or other expression languages. Runtime evaluation and evidence production belong to the executing or verifying system. The envelope records the declared condition, result, and evidence references without claiming that the expression engine itself is standardized here.

Artifact references are also not dereferenced or content-verified by this prototype. Their digests are envelope metadata unless an integrating system supplies an artifact resolver.

## Relationship to CML

CML checks causal lineage such as missing parents, ambiguous roots, and broken responsibility paths. CAEP provides a portable envelope carrying those relationships across multi-server MCP workflows while recording postconditions and recovery.

The absurdity trajectory shows how stale observations, late-recorded parallel events, and individually correct tools can create a globally invalid state. The recovery episode points directly to the digest-bound divergence episode, preserving the reason payment B was cancelled.

This prototype is intentionally non-normative. `org.causal-memory-layer.caep` and the `$id` URN are working identifiers, not official MCP registrations or security certification.

Disclosure: prepared with AI assistance under human direction and review.
