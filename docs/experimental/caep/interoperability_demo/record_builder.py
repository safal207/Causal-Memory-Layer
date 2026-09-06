from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from common import read_json, sha256_json

PROFILE = "org.causal-memory-layer.caep"
SCHEMA_VERSION = "0.1.0"
DIGEST_COVERAGE = (
    "all fields except integrity.record_digest and integrity.signature"
)


def canonical_record_bytes(record: dict[str, Any]) -> bytes:
    """Return CAEP JSON v1 canonical bytes."""
    canonical = copy.deepcopy(record)
    canonical["integrity"].pop("record_digest", None)
    canonical["integrity"].pop("signature", None)
    return json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def seal(record: dict[str, Any]) -> dict[str, Any]:
    """Attach the computed CAEP record digest."""
    record["integrity"]["record_digest"] = {
        "algorithm": "sha256",
        "value": hashlib.sha256(canonical_record_bytes(record)).hexdigest(),
    }
    return record


def artifact(path: Path, ref: str) -> dict[str, Any]:
    """Describe one deterministic JSON artifact."""
    value = read_json(path)
    return {
        "ref": ref,
        "media_type": "application/json",
        "digest": {"algorithm": "sha256", "value": sha256_json(value)},
        "classification": "internal",
    }


def build_record(
    *,
    episode_id: str,
    workflow_id: str,
    status: str,
    order_id: str,
    action_tool: str,
    request_path: Path,
    response_path: Path,
    verification_path: Path,
    state_before_path: Path,
    state_after_path: Path,
    started_at: str,
    completed_at: str,
    observed_at: str,
    verified_at: str,
    verification_verdict: str,
    verification_result: str,
    recovery_status: str,
    parent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and seal a CAEP record from cross-process artifacts."""
    parent_ids = [parent["episode_id"]] if parent else []
    parent_digests = {}
    if parent:
        parent_digests[parent["episode_id"]] = parent["integrity"][
            "record_digest"
        ]

    accepted = status in {"verified", "recovered"}
    postcondition_id = (
        "single_successful_payment_restored"
        if status == "recovered"
        else "single_successful_payment"
    )
    record = {
        "profile": PROFILE,
        "schema_version": SCHEMA_VERSION,
        "episode_id": episode_id,
        "workflow_id": workflow_id,
        "status": status,
        "causal_parent_ids": parent_ids,
        "supersedes": [],
        "intent": {
            "request_ref": f"urn:demo:request:{episode_id}",
            "initiator": {
                "ref": "urn:actor:demo-user",
                "type": "human",
            },
            "code": (
                "RESTORE_SINGLE_PAYMENT"
                if status == "recovered"
                else "PAY_ORDER_IF_UNPAID"
            ),
            "summary": "Preserve exactly one successful payment for the order.",
            "constraints": ["maximum_one_successful_payment"],
        },
        "authorization": {
            "decision": "authorized",
            "scope": {
                "action": f"payments.{action_tool}",
                "resource": f"urn:order:{order_id}",
                "constraints": ["maximum_one_successful_payment"],
            },
            "approval_refs": [f"urn:demo:approval:{episode_id}"],
            "policy_refs": ["urn:demo:policy:single-payment-v1"],
            "actor": {
                "ref": "urn:policy-engine:demo",
                "type": "policy_engine",
            },
            "expires_at": "2026-07-29T18:00:00Z",
        },
        "decision": {
            "code": (
                "EXECUTE_COMPENSATING_TRANSITION"
                if status == "recovered"
                else "EXECUTE_AUTHORIZED_TRANSITION"
            ),
            "maker": {
                "ref": "urn:agent:demo-orchestrator",
                "type": "agent",
            },
            "reason_codes": [
                "RECOVERY_POLICY_PASSED"
                if status == "recovered"
                else "PRECONDITIONS_SATISFIED"
            ],
            "record_ref": f"urn:demo:decision:{episode_id}",
            "summary": (
                "Execute the smallest bounded action and verify the ledger "
                "independently."
            ),
        },
        "state_before": [
            artifact(
                state_before_path,
                f"urn:demo:artifact:{episode_id}:before",
            )
        ],
        "action": {
            "side_effect": "external_write",
            "blast_radius": "single_resource",
            "dispatch": {
                "executor": {
                    "ref": "urn:mcp-server:payment-writer",
                    "type": "mcp_server",
                },
                "server_ref": "urn:mcp-server:payment-writer",
                "tool_name": action_tool,
                "protocol_version": "2026-07-28",
                "request_ref": f"urn:demo:artifact:{episode_id}:request",
                "request_digest": {
                    "algorithm": "sha256",
                    "value": sha256_json(read_json(request_path)),
                },
                "tool_schema_digest": {
                    "algorithm": "sha256",
                    "value": "2" * 64,
                },
                "correlation_id": f"corr_{episode_id}",
                "idempotency_key": f"idem_{episode_id}",
                "started_at": started_at,
                "completed_at": completed_at,
            },
        },
        "expected_postconditions": [
            {
                "id": postcondition_id,
                "language": "human_review",
                "expression": "successful_payment_count == 1",
                "severity": "critical",
                "evidence_refs": [
                    f"urn:demo:artifact:{episode_id}:verification"
                ],
            }
        ],
        "outcome": {
            "status": "succeeded",
            "result_type": "completed",
            "response_ref": f"urn:demo:artifact:{episode_id}:response",
            "response_digest": {
                "algorithm": "sha256",
                "value": sha256_json(read_json(response_path)),
            },
            "observed_at": observed_at,
        },
        "state_after": [
            artifact(
                state_after_path,
                f"urn:demo:artifact:{episode_id}:after",
            )
        ],
        "verification": {
            "verdict": verification_verdict,
            "independence": "independent",
            "verifier": {
                "ref": "urn:verifier:independent-ledger-reader",
                "type": "verifier",
            },
            "checks": [
                {
                    "id": f"check_{episode_id}",
                    "postcondition_id": postcondition_id,
                    "result": verification_result,
                    "evidence_refs": [
                        f"urn:demo:artifact:{episode_id}:verification"
                    ],
                }
            ],
            "verified_at": verified_at,
        },
        "recovery": {
            "reversibility": "compensatable",
            "status": recovery_status,
            "rollback_tool": (
                "cancel_payment"
                if action_tool == "create_payment"
                else "restore_cancelled_payment"
            ),
            "action_refs": [
                f"urn:demo:artifact:{episode_id}:verification"
            ],
        },
        "time": {
            "valid_time": completed_at,
            "recorded_time": verified_at,
            "source_clock": "demo.local",
        },
        "integrity": {
            "record_digest": {
                "algorithm": "sha256",
                "value": "0" * 64,
            },
            "parent_digests": parent_digests,
            "canonicalization": "caep-json-v1",
            "digest_coverage": DIGEST_COVERAGE,
        },
        "privacy": {
            "classification": "internal",
            "contains_personal_data": False,
            "redacted_paths": [],
        },
        "extensions": {
            "org.causal-memory-layer.interoperability-demo": {
                "transport": "filesystem-json",
                "accepted_transition": accepted,
                "verification_artifact_digest": sha256_json(
                    read_json(verification_path)
                ),
            }
        },
    }
    return seal(record)
