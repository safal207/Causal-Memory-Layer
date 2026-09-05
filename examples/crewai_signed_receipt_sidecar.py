"""CrewAI-style signed receipt sidecar demo using CML.

This example builds on ``crewai_style_causal_audit.py`` and shows how a
structured agent trace can carry receipt-shaped integrity metadata without
changing CML core semantics.

Important non-claims:

- this is not production cryptographic signing;
- this is not wallet identity or key management;
- this is not third-party safety certification;
- this is only a dependency-free receipt-shaped sidecar demo.

Run from the repository root after installing the package:

    pip install -e .
    python examples/crewai_signed_receipt_sidecar.py

Expected behavior:

1. CML still reports structural causal findings, such as
   ``CML-AUDIT-R1-MISSING_PARENT`` for the intentionally broken parent.
2. The receipt sidecar verifies deterministic hash integrity for each record.
3. A simulated tamper check shows that modifying a record after receipt
   creation changes the expected receipt hash.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from cml.audit import AuditEngine
from cml.record import CausalRecord
from crewai_style_causal_audit import make_crewai_style_trace


DEMO_SIGNATURE_SCHEME = "demo-hash-only"


def canonical_json(value: Any) -> str:
    """Return deterministic JSON for hashing and display."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    """Return a SHA-256 hex digest for UTF-8 text."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def object_hash(record: CausalRecord) -> str:
    """Hash the record object/payload in a deterministic way."""

    return sha256_text(canonical_json(record.object))


def receipt_payload(record: CausalRecord) -> dict[str, Any]:
    """Build the receipt payload that would be signed by an advanced layer."""

    return {
        "action_id": record.id,
        "parent_action_id": record.parent_cause,
        "task_id": record.permitted_by,
        "agent_id": record.actor.comm,
        "timestamp": record.timestamp,
        "action": record.action,
        "object_hash": object_hash(record),
    }


def build_demo_receipt(record: CausalRecord) -> dict[str, str]:
    """Create receipt-shaped metadata for a CausalRecord.

    This intentionally uses a deterministic hash instead of a cryptographic
    signature. A real deployment could replace this sidecar with Ed25519,
    wallet-based signing, HSM-backed signing, or another verifier-specific
    scheme without changing the CML structural audit primitive.
    """

    payload = receipt_payload(record)
    payload_hash = sha256_text(canonical_json(payload))
    receipt = {
        "signature_scheme": DEMO_SIGNATURE_SCHEME,
        "key_ref": f"agent:{record.actor.comm or 'unknown'}",
        "payload_hash": payload_hash,
        "receipt_hash": sha256_text(
            canonical_json(
                {
                    "payload_hash": payload_hash,
                    "signature_scheme": DEMO_SIGNATURE_SCHEME,
                    "key_ref": f"agent:{record.actor.comm or 'unknown'}",
                }
            )
        ),
    }
    return receipt


def attach_demo_receipts(records: list[CausalRecord]) -> None:
    """Attach compact receipt metadata to ``record.integrity``."""

    for record in records:
        record.integrity = canonical_json(build_demo_receipt(record))


def parse_integrity(record: CausalRecord) -> dict[str, Any]:
    if record.integrity is None:
        return {}
    if isinstance(record.integrity, str):
        return json.loads(record.integrity)
    # Defensive fallback: older experimental callers may store a dict.
    return dict(record.integrity)


def verify_demo_receipts(records: list[CausalRecord]) -> list[dict[str, Any]]:
    """Verify receipt-shaped metadata against the current record contents."""

    results: list[dict[str, Any]] = []
    for record in records:
        actual = parse_integrity(record)
        expected = build_demo_receipt(record)
        results.append(
            {
                "record_id": record.id,
                "agent_id": record.actor.comm,
                "signature_scheme": actual.get("signature_scheme"),
                "key_ref": actual.get("key_ref"),
                "receipt_hash_matches": actual.get("receipt_hash")
                == expected["receipt_hash"],
                "payload_hash_matches": actual.get("payload_hash")
                == expected["payload_hash"],
            }
        )
    return results


def main() -> None:
    records = make_crewai_style_trace()
    attach_demo_receipts(records)

    audit_result = AuditEngine().run(records)
    receipt_result = verify_demo_receipts(records)

    print("CML structural audit result")
    print(json.dumps(audit_result.to_dict(), indent=2))

    print("\nReceipt-shaped sidecar verification")
    print(json.dumps(receipt_result, indent=2))

    tampered_records = copy.deepcopy(records)
    tampered_records[-1].object["recipient"] = "tampered@example.com"
    tamper_result = verify_demo_receipts(tampered_records)

    print("\nSimulated tamper check")
    print(json.dumps(tamper_result[-1], indent=2))


if __name__ == "__main__":
    main()
