# Portable Causal Action Episode (CAEP) — experimental v0.1.0

CAEP is an experimental execution-record profile for Causal Memory Layer (CML) and MCP workflows:

`observable state → intent → authorization → decision → exact tool dispatch → outcome → independent verification → recovery`

It complements ordinary logs and provenance traces by checking whether a tool action was an authorized, observable, digest-bound, and verifiable state transition.

## Components

- `caep.schema.json` — JSON Schema Draft 2020-12.
- `caep.example.json` — independently verified successful external write.
- `caep.diverged.example.json` — duplicate-payment divergence and containment.
- `caep.recovered.example.json` — digest-bound compensation record.
- `caep.absurdity-trajectory.json` and `ABSURDITY_TRAJECTORY.md` — multidimensional failure-injection scenario and guardrails.
- `validate_caep.py` and `test_validate_caep.py` — schema, semantic, digest, duplicate-key, temporal-order, lifecycle, and parent-binding validation.
- `interoperability_demo/` — transport-neutral cross-process demo.
- `mcp_sdk_adapter/` — real official MCP Python SDK sessions over stdio with separate action and verifier servers.
- `trust_console/` — dependency-free browser viewer for human-readable Trust Receipts.

## Open the verified MCP demo

Public Trust Console:

`https://safal207.github.io/Causal-Memory-Layer/trust-console/`

Choose **Load official MCP SDK demo**. The console downloads the CI-generated canonical JSON bundle, recomputes SHA-256 against the published provenance manifest, and presents the happy, divergence, and digest-bound recovery records as human-readable receipts.

The source runtime bundle was reproduced byte-for-byte on Python 3.10, 3.11, and 3.12. The published canonical representation has SHA-256:

`b4765f234c9020e3c48c6b7d0f6834d14a93d934cc2cdc8644f9084976a03c36`

The browser viewer is a presentation and integrity-preview layer. The Python validator remains the normative prototype validation path.

## Run through the official MCP Python SDK

From the repository root:

```bash
python -m pip install -e ".[mcp]"
python docs/experimental/caep/mcp_sdk_adapter/run_adapter.py \
  --output /tmp/caep-mcp-sdk-bundle.json
```

This performs real MCP initialization, tool discovery, action calls, independent verification, divergence detection, compensation, and digest-bound recovery over two separate stdio server processes.

## View locally

From `docs/experimental/caep/`:

```bash
python -m http.server 8000
```

Open `http://localhost:8000/trust_console/`, load a demo, upload a generated bundle, or paste a CAEP record.

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

python -m unittest docs/experimental/caep/test_validate_caep.py
```

A non-root record is valid only when every ID in `causal_parent_ids` is supplied and its content digest is recomputed successfully.

## Integrity model

`caep-json-v1` uses UTF-8 JSON with object keys sorted, no insignificant whitespace, non-ASCII text preserved, and non-finite numbers rejected.

The record SHA-256 covers every field except:

- `integrity.record_digest`;
- `integrity.signature`.

Every causal parent requires a matching `integrity.parent_digests` entry. The validator recomputes the parent's record digest and the child's binding and rejects missing or undeclared parents.

Digests establish integrity, not authenticity. The examples do not claim a trust anchor, signature-verification policy, production guarantee, official MCP registration, or security certification.

## Accepted-transition rules

For `status=verified` and `status=recovered`:

- `verification.verdict` is `verified`;
- `verification.independence` is `independent`;
- verifier, executor, and decision maker are distinct where required;
- every declared postcondition has a check;
- every check passes;
- accepted writes or destructive transitions contain at least one passing `critical` postcondition.

`completed` is weaker and does not imply independent business acceptance.

## Temporal scope

The validator enforces offset-aware timestamps and these relations when present:

```text
valid_time ≤ recorded_time
dispatch.started_at ≤ dispatch.completed_at
dispatch.completed_at ≤ outcome.observed_at
outcome.observed_at ≤ verification.verified_at
dispatch.started_at ≤ authorization.expires_at
```

Cross-record temporal contradictions belong to the trajectory or bundle layer.

## Core invariants

1. Intent, authorization, decision, dispatch, outcome, and verification remain separate.
2. Tool success is not business success until declared postconditions pass.
3. Checks cannot target undeclared postconditions.
4. Accepted transitions require an identified independent verifier.
5. `recovered` requires verified recovery and preserved causal history.
6. Writes and destructive actions require explicit authorization and recovery metadata.
7. Valid time and recorded time remain distinct.
8. Every declared causal parent is supplied and content-verified.
9. Malformed or duplicate-key JSON fails closed.
10. Decision records contain reason codes and evidence references, not private chain-of-thought.
11. Recovery follows the smallest justified reversible action toward the declared target state.

## Runtime boundary

CAEP records postcondition expressions but does not standardize or execute CEL, JSONPath, Rego, SQL, or another expression language. Runtime evaluation, evidence production, artifact resolution, and authentication remain responsibilities of the integrating system.

CML checks causal lineage such as missing parents, ambiguous roots, and broken responsibility paths. CAEP carries those relationships across multi-server MCP workflows while recording postconditions and recovery.

Disclosure: prepared with AI assistance under human direction and review.
