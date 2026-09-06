# Signed Causal Receipts

## Purpose

This research note captures a future extension for CML.

```text
CML verifies causality.
Signed receipts add authorship evidence.
Temporal provenance records when the causal claim entered the chain.
```

## Core idea

CML can already help answer whether a causal graph is internally well-formed.

A signed causal receipt would add an optional evidence envelope around a causal record so external reviewers can inspect not only the parent chain, but also the claimed author and timing metadata.

This should stay optional. CML core should continue to support simple unsigned traces.

## Draft receipt fields

```text
CausalReceipt {
  action_id
  parent_action_id | null
  task_id | null
  agent_id
  timestamp
  observed_at | null
  sequence_no | null
  previous_receipt_hash | null
  payload_hash | null
  hash_alg | null
  signer_ref | null
  signature_ref | null
  signature_alg | null
}
```

## Layers

1. Structural causality: parent links, roots, missing parents, cycles.
2. Content integrity: optional payload hash over minimized references.
3. Authorship evidence: optional signer and signature references.
4. Temporal provenance: timestamp, observed time, sequence number, previous receipt hash.
5. Cross-session provenance: recalled memory can carry a receipt or receipt reference.

## Relationship to ProofPath

ProofPath evidence bundles could eventually include causal receipts:

```text
proofpath-evidence/
  manifest.json
  decisions.jsonl
  causal-receipts.jsonl
  hash-chain.json
  verifier-result.json
  privacy-report.json
```

This creates the bridge:

```text
CML + signed causal receipts + ProofPath evidence bundle
= portable, offline-verifiable causal evidence for AI-agent actions
```

## Non-claims

This note does not claim production identity infrastructure, trusted timestamping, blockchain anchoring, regulatory compliance, runtime blocking, or replacement of CML core audit rules.

The narrow claim is:

```text
Signed causal receipts may make CML traces more portable and independently reviewable.
```

## Next step

Create a small fixture contract before implementation:

- valid unsigned chain;
- valid receipt chain;
- unresolved signer reference;
- broken parent chain;
- missing temporal sequence.
