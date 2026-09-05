# Signed Receipt Sidecar for CML

Status: experimental example pattern.

This note documents a small optional sidecar pattern for attaching receipt-shaped integrity metadata to CML records.

The goal is to keep CML core focused on structural causal validity while showing a possible path toward stronger authorship and tamper-evidence workflows.

## Why this exists

CML core answers a narrow structural question:

```text
Does this action have a valid causal parent / responsibility path?
```

For example, the core audit can detect that a record points to a missing `parent_cause`, creating `CML-AUDIT-R1-MISSING_PARENT`.

A separate question is authorship:

```text
Can a third party verify that the claimed agent actually authored or authorized this action link?
```

That question needs integrity metadata, signatures, key references, or wallet/HSM-backed verification. Those concerns are intentionally outside the base CML audit engine.

## Layer split

| Layer | Scope | Claim |
|---|---|---|
| CML core | Validate structural causal lineage | Missing parents, ambiguous roots, broken chains |
| Receipt sidecar | Attach receipt-shaped integrity metadata | Demonstrates a possible tamper-evidence path |
| Advanced signing layer | Real signatures / wallets / key management | Out of scope for this demo |

## Demo

Run:

```bash
pip install -e .
python examples/crewai_signed_receipt_sidecar.py
```

The demo:

1. builds a small CrewAI-style causal trace;
2. attaches deterministic receipt-shaped metadata to `record.integrity`;
3. runs the normal CML structural audit;
4. verifies that the sidecar metadata still matches the record contents;
5. simulates tampering by changing the final record after receipt creation.

## Receipt shape

The demo computes a deterministic payload from:

```text
action_id
parent_action_id | null
task_id | null
agent_id
timestamp
action
object_hash
```

Then it stores compact receipt metadata in `record.integrity`:

```json
{
  "signature_scheme": "demo-hash-only",
  "key_ref": "agent:assistant_agent",
  "payload_hash": "...",
  "receipt_hash": "..."
}
```

## Non-claims

This demo does not claim to provide:

- production cryptographic signing;
- wallet identity;
- key management;
- third-party safety certification;
- compliance evidence;
- complete tamper-proof logging.

The narrow claim is:

```text
CML can keep structural causal validation separate from optional integrity metadata.
```

A production implementation could replace `demo-hash-only` with Ed25519, HSM-backed signing, wallet-based signing, or another verifier-specific scheme.

## Why not put this in CML core immediately?

Because structural lineage and authorship verification are different problems.

Keeping them separate makes the first integration path simpler:

- no new runtime dependency;
- no key-management claim;
- no wallet/security overclaim;
- no change to the audit engine;
- easy reviewer reproduction.

This keeps the CrewAI-style proof path small while preserving a clean upgrade path for signed receipts later.
