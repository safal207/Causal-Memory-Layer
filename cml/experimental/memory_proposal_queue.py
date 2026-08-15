#!/usr/bin/env python3
"""Read-only audit for CML automatic memory proposal queues.

The auditor measures queue pressure and repeated review-envelope structure. It does
not decide whether two Memory Packs are semantically duplicate and it never grants
merge, close, acceptance, execution, or policy-mutation authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SNAPSHOT_SCHEMA = "cml.memory-proposal-queue.snapshot.v0.1"
RESULT_SCHEMA = "cml.memory-proposal-queue.audit.v0.1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class QueueAuditError(ValueError):
    pass


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise QueueAuditError(f"{field} must be an ISO-8601 timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise QueueAuditError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise QueueAuditError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise QueueAuditError(f"{field} must be a positive integer")
    return value


def _false(value: Any, field: str) -> bool:
    if value is not False:
        raise QueueAuditError(f"{field} must be false")
    return False


def _proposal(raw: Any, captured_at: datetime) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise QueueAuditError("each proposal must be an object")

    proposal_pr = _positive_int(raw.get("proposal_pr"), "proposal_pr")
    source_pr = _positive_int(raw.get("source_pr"), f"proposal {proposal_pr}.source_pr")

    source_merge = raw.get("source_merge")
    if not isinstance(source_merge, str) or not HEX40.fullmatch(source_merge):
        raise QueueAuditError(f"proposal {proposal_pr}.source_merge must be a 40-char lowercase hex SHA")

    pack_id = raw.get("pack_id")
    if not isinstance(pack_id, str) or not HEX64.fullmatch(pack_id):
        raise QueueAuditError(f"proposal {proposal_pr}.pack_id must be a 64-char lowercase hex digest")

    if raw.get("state") != "open":
        raise QueueAuditError(f"proposal {proposal_pr}.state must be open")
    if raw.get("draft") is not True:
        raise QueueAuditError(f"proposal {proposal_pr}.draft must be true")
    if raw.get("lesson_status") != "proposed":
        raise QueueAuditError(f"proposal {proposal_pr}.lesson_status must be proposed")
    if raw.get("visibility") != "team":
        raise QueueAuditError(f"proposal {proposal_pr}.visibility must be team")
    if raw.get("contains_private_data") is not True:
        raise QueueAuditError(f"proposal {proposal_pr}.contains_private_data must be true")
    _false(raw.get("merge_authority"), f"proposal {proposal_pr}.merge_authority")
    _false(raw.get("execution_authority"), f"proposal {proposal_pr}.execution_authority")

    created_at_raw = raw.get("created_at")
    created_at = None
    age_days = None
    if created_at_raw is not None:
        created_at = _parse_time(created_at_raw, f"proposal {proposal_pr}.created_at")
        if created_at > captured_at:
            raise QueueAuditError(f"proposal {proposal_pr}.created_at cannot be after captured_at")
        age_days = (captured_at - created_at).total_seconds() / 86400.0

    envelope = {
        "state": "open",
        "draft": True,
        "lesson_status": "proposed",
        "visibility": "team",
        "contains_private_data": True,
        "merge_authority": False,
        "execution_authority": False,
    }

    return {
        "proposal_pr": proposal_pr,
        "source_pr": source_pr,
        "source_merge": source_merge,
        "pack_id": pack_id,
        "created_at": created_at,
        "age_days": age_days,
        "envelope": envelope,
    }


def _pressure(count: int) -> str:
    if count >= 30:
        return "CRITICAL_REVIEW_PRESSURE"
    if count >= 20:
        return "HIGH_REVIEW_PRESSURE"
    if count >= 10:
        return "ELEVATED_REVIEW_PRESSURE"
    return "BOUNDED_REVIEW_PRESSURE"


def _digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def audit(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise QueueAuditError("top-level payload must be an object")
    if payload.get("schema") != SNAPSHOT_SCHEMA:
        raise QueueAuditError(f"schema must be {SNAPSHOT_SCHEMA}")

    captured_at = _parse_time(payload.get("captured_at"), "captured_at")
    main_revision = payload.get("main_revision")
    if not isinstance(main_revision, str) or not HEX40.fullmatch(main_revision):
        raise QueueAuditError("main_revision must be a 40-char lowercase hex SHA")

    proposals_raw = payload.get("proposals")
    if not isinstance(proposals_raw, list) or not proposals_raw:
        raise QueueAuditError("proposals must be a non-empty list")

    reported_total = _positive_int(payload.get("reported_total_count"), "reported_total_count")
    if reported_total != len(proposals_raw):
        raise QueueAuditError(
            "snapshot coverage incomplete: reported_total_count must equal the number of proposals"
        )

    proposals = [_proposal(raw, captured_at) for raw in proposals_raw]

    for key in ("proposal_pr", "source_pr", "source_merge", "pack_id"):
        values = [item[key] for item in proposals]
        if len(set(values)) != len(values):
            raise QueueAuditError(f"duplicate {key} detected")

    envelope_keys = [
        json.dumps(item["envelope"], sort_keys=True, separators=(",", ":"))
        for item in proposals
    ]
    envelope_counts = Counter(envelope_keys)
    dominant_envelope_count = max(envelope_counts.values())
    envelope_share = dominant_envelope_count / len(proposals)

    dated = [item for item in proposals if item["created_at"] is not None]
    ages = [item["age_days"] for item in dated if item["age_days"] is not None]
    oldest = min((item["created_at"] for item in dated), default=None)
    newest = max((item["created_at"] for item in dated), default=None)

    pressure = _pressure(len(proposals))
    aged_14d_known = sum(1 for age in ages if age >= 14.0)
    oldest_known_age = max(ages) if ages else None

    snapshot_identity = {
        "schema": SNAPSHOT_SCHEMA,
        "captured_at": captured_at.isoformat(),
        "main_revision": main_revision,
        "reported_total_count": reported_total,
        "proposal_prs": sorted(item["proposal_pr"] for item in proposals),
        "source_merges": sorted(item["source_merge"] for item in proposals),
        "pack_ids": sorted(item["pack_id"] for item in proposals),
    }

    if pressure in {"CRITICAL_REVIEW_PRESSURE", "HIGH_REVIEW_PRESSURE"}:
        next_safe_transition = "QUEUE_LEVEL_GROUP_REVALIDATE_THEN_REVIEW"
    elif pressure == "ELEVATED_REVIEW_PRESSURE":
        next_safe_transition = "BATCH_REVALIDATE_THEN_REVIEW"
    else:
        next_safe_transition = "REVIEW_WITH_CURRENT_CONTRACT_REVALIDATION"

    return {
        "schema": RESULT_SCHEMA,
        "mode": "REVIEW_ADVISORY_ONLY",
        "authority_granted": False,
        "merge_authority": False,
        "close_authority": False,
        "acceptance_authority": False,
        "policy_mutation_authority": False,
        "main_revision": main_revision,
        "captured_at": captured_at.isoformat(),
        "queue": {
            "proposal_count": len(proposals),
            "pressure": pressure,
            "unique_source_pr_count": len({item["source_pr"] for item in proposals}),
            "unique_source_merge_count": len({item["source_merge"] for item in proposals}),
            "unique_pack_id_count": len({item["pack_id"] for item in proposals}),
        },
        "age": {
            "coverage_count": len(dated),
            "coverage_ratio": round(len(dated) / len(proposals), 6),
            "distribution_status": "COMPLETE" if len(dated) == len(proposals) else "PARTIAL",
            "oldest_known_created_at": oldest.isoformat() if oldest else None,
            "newest_known_created_at": newest.isoformat() if newest else None,
            "oldest_known_age_days": round(oldest_known_age, 3) if oldest_known_age is not None else None,
            "aged_14d_known_count": aged_14d_known,
        },
        "review_envelope": {
            "unique_envelope_count": len(envelope_counts),
            "dominant_envelope_count": dominant_envelope_count,
            "dominant_envelope_share": round(envelope_share, 6),
            "structural_repetition_count": len(proposals) - len(envelope_counts),
            "semantic_duplicate_status": "NOT_MEASURED",
            "semantic_duplicate_claim": False,
        },
        "ancestry": {
            "status": "NOT_MEASURED",
            "claim": "source commit ancestry/current applicability requires a separate exact-main revalidation pass",
        },
        "next_safe_transition": next_safe_transition,
        "recommendations": [
            "group proposals for review planning without merging or closing them",
            "revalidate each selected pack against current applicability/information-quality contracts before acceptance",
            "measure source ancestry/current-main drift separately; do not infer it from queue age",
            "preserve distinct pack identities even when the review envelope is structurally repeated",
        ],
        "non_claims": [
            "structural review-envelope repetition is not semantic Memory Pack duplication",
            "queue age does not invalidate historical evidence",
            "queue pressure does not authorize automatic acceptance, closure, merge, or deletion",
            "this audit does not establish current source ancestry or applicability",
        ],
        "snapshot_digest": _digest(snapshot_identity),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a normalized CML memory proposal queue snapshot")
    parser.add_argument("input", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        result = audit(payload)
    except (OSError, json.JSONDecodeError, QueueAuditError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2

    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
