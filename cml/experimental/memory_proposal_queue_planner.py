#!/usr/bin/env python3
"""Read-only grouping and revalidation planner for CML memory proposals.

The planner consumes source-owned CML applicability and information-quality
results, composes them through the canonical information-fitness gate, and emits
one advisory decision record per Memory Pack. Grouping is review ergonomics only:
it never collapses pack identity and never grants merge, close, acceptance,
execution, or policy-mutation authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cml.integrations.information_fitness import (
    InformationFitnessStatus,
    evaluate_information_fitness,
)
from cml.integrations.information_quality import (
    CompletenessStatus,
    InformationQualityResult,
    QualityReadiness,
    RelevanceStatus,
    SemanticTruthStatus,
)
from cml.integrations.memory_applicability import (
    ApplicabilityResult,
    ApplicabilityStatus,
)

INPUT_SCHEMA = "cml.memory-proposal-queue.revalidation-input.v0.2"
RESULT_SCHEMA = "cml.memory-proposal-queue.revalidation-plan.v0.2"
SOURCE_AUDIT_SCHEMA = "cml.memory-proposal-queue.audit.v0.1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SHA256_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


class QueuePlanningError(ValueError):
    pass


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise QueuePlanningError(f"{field} must be a positive integer")
    return value


def _nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise QueuePlanningError(f"{field} must be a non-empty string")
    return value.strip()


def _parse_time(value: Any, field: str) -> datetime:
    text = _nonempty(value, field)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise QueuePlanningError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise QueuePlanningError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _string_tuple(value: Any, field: str, *, require_nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise QueuePlanningError(f"{field} must be a list")
    normalized = tuple(_nonempty(item, f"{field} entry") for item in value)
    if require_nonempty and not normalized:
        raise QueuePlanningError(f"{field} must not be empty")
    if len(set(normalized)) != len(normalized):
        raise QueuePlanningError(f"{field} entries must be unique")
    return normalized


def _enum(enum_type, value: Any, field: str):
    text = _nonempty(value, field)
    try:
        return enum_type(text)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise QueuePlanningError(f"{field} must be one of: {allowed}") from exc


def _digest(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _record(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise QueuePlanningError("each record must be an object")

    proposal_pr = _positive_int(raw.get("proposal_pr"), "proposal_pr")
    source_pr = _positive_int(raw.get("source_pr"), f"proposal {proposal_pr}.source_pr")

    source_merge = raw.get("source_merge")
    if not isinstance(source_merge, str) or not HEX40.fullmatch(source_merge):
        raise QueuePlanningError(
            f"proposal {proposal_pr}.source_merge must be a 40-char lowercase hex SHA"
        )

    pack_id = raw.get("pack_id")
    if not isinstance(pack_id, str) or not HEX64.fullmatch(pack_id):
        raise QueuePlanningError(
            f"proposal {proposal_pr}.pack_id must be a 64-char lowercase hex digest"
        )

    lineage_root_id = _nonempty(
        raw.get("lineage_root_id"),
        f"proposal {proposal_pr}.lineage_root_id",
    )
    lineage_evidence_refs = _string_tuple(
        raw.get("lineage_evidence_refs"),
        f"proposal {proposal_pr}.lineage_evidence_refs",
        require_nonempty=True,
    )
    gate_evidence_refs = _string_tuple(
        raw.get("gate_evidence_refs"),
        f"proposal {proposal_pr}.gate_evidence_refs",
        require_nonempty=True,
    )

    applicability_raw = raw.get("applicability")
    if not isinstance(applicability_raw, dict):
        raise QueuePlanningError(f"proposal {proposal_pr}.applicability must be an object")
    applicability = ApplicabilityResult(
        status=_enum(
            ApplicabilityStatus,
            applicability_raw.get("status"),
            f"proposal {proposal_pr}.applicability.status",
        ),
        reasons=_string_tuple(
            applicability_raw.get("reasons"),
            f"proposal {proposal_pr}.applicability.reasons",
        ),
    )

    quality_raw = raw.get("quality")
    if not isinstance(quality_raw, dict):
        raise QueuePlanningError(f"proposal {proposal_pr}.quality must be an object")
    quality = InformationQualityResult(
        semantic_truth=_enum(
            SemanticTruthStatus,
            quality_raw.get("semantic_truth"),
            f"proposal {proposal_pr}.quality.semantic_truth",
        ),
        completeness=_enum(
            CompletenessStatus,
            quality_raw.get("completeness"),
            f"proposal {proposal_pr}.quality.completeness",
        ),
        relevance=_enum(
            RelevanceStatus,
            quality_raw.get("relevance"),
            f"proposal {proposal_pr}.quality.relevance",
        ),
        readiness=_enum(
            QualityReadiness,
            quality_raw.get("readiness"),
            f"proposal {proposal_pr}.quality.readiness",
        ),
        reasons=_string_tuple(
            quality_raw.get("reasons"),
            f"proposal {proposal_pr}.quality.reasons",
        ),
    )

    canonical_fitness = evaluate_information_fitness(
        applicability=applicability,
        quality=quality,
    )
    claimed_fitness = _enum(
        InformationFitnessStatus,
        raw.get("claimed_fitness_status"),
        f"proposal {proposal_pr}.claimed_fitness_status",
    )
    if claimed_fitness is not canonical_fitness.status:
        raise QueuePlanningError(
            f"proposal {proposal_pr}.claimed_fitness_status contradicts canonical CML fitness"
        )

    return {
        "proposal_pr": proposal_pr,
        "source_pr": source_pr,
        "source_merge": source_merge,
        "pack_id": pack_id,
        "lineage_root_id": lineage_root_id,
        "lineage_evidence_refs": lineage_evidence_refs,
        "gate_evidence_refs": gate_evidence_refs,
        "applicability": applicability,
        "quality": quality,
        "fitness": canonical_fitness,
    }


def _route(status: InformationFitnessStatus) -> str:
    if status is InformationFitnessStatus.NOT_FIT:
        return "BLOCK_ACCEPTANCE_PENDING_NEW_EVIDENCE_OR_CONTEXT"
    if status is InformationFitnessStatus.REVIEW_REQUIRED:
        return "HUMAN_REVALIDATION_REQUIRED"
    if status is InformationFitnessStatus.READY_FOR_AUTHORITY_CHECK:
        return "ELIGIBLE_FOR_SEPARATE_ACCEPTANCE_REVIEW"
    raise QueuePlanningError("unmapped information fitness status")


def plan(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise QueuePlanningError("top-level payload must be an object")
    if payload.get("schema") != INPUT_SCHEMA:
        raise QueuePlanningError(f"schema must be {INPUT_SCHEMA}")
    if payload.get("source_audit_schema") != SOURCE_AUDIT_SCHEMA:
        raise QueuePlanningError(f"source_audit_schema must be {SOURCE_AUDIT_SCHEMA}")

    source_audit_digest = payload.get("source_audit_digest")
    if not isinstance(source_audit_digest, str) or not SHA256_REF.fullmatch(source_audit_digest):
        raise QueuePlanningError("source_audit_digest must be a sha256: digest")

    current_main_revision = payload.get("current_main_revision")
    if not isinstance(current_main_revision, str) or not HEX40.fullmatch(current_main_revision):
        raise QueuePlanningError("current_main_revision must be a 40-char lowercase hex SHA")

    captured_at = _parse_time(payload.get("captured_at"), "captured_at")
    synthetic = payload.get("synthetic")
    if not isinstance(synthetic, bool):
        raise QueuePlanningError("synthetic must be boolean")

    records_raw = payload.get("records")
    if not isinstance(records_raw, list) or not records_raw:
        raise QueuePlanningError("records must be a non-empty list")
    expected_record_count = _positive_int(
        payload.get("expected_record_count"),
        "expected_record_count",
    )
    if expected_record_count != len(records_raw):
        raise QueuePlanningError(
            "revalidation coverage incomplete: expected_record_count must equal records length"
        )

    records = [_record(raw) for raw in records_raw]
    for key in ("proposal_pr", "source_pr", "source_merge", "pack_id"):
        values = [record[key] for record in records]
        if len(values) != len(set(values)):
            raise QueuePlanningError(f"duplicate {key} detected")

    decision_records: list[dict[str, Any]] = []
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for record in records:
        fitness = record["fitness"]
        decision_identity = {
            "proposal_pr": record["proposal_pr"],
            "pack_id": record["pack_id"],
            "lineage_root_id": record["lineage_root_id"],
            "current_main_revision": current_main_revision,
            "applicability_status": record["applicability"].status.value,
            "quality_readiness": record["quality"].readiness.value,
            "fitness_status": fitness.status.value,
            "lineage_evidence_refs": sorted(record["lineage_evidence_refs"]),
            "gate_evidence_refs": sorted(record["gate_evidence_refs"]),
        }
        decision = {
            "decision_id": _digest(decision_identity),
            "proposal_pr": record["proposal_pr"],
            "source_pr": record["source_pr"],
            "source_merge": record["source_merge"],
            "pack_id": record["pack_id"],
            "lineage_root_id": record["lineage_root_id"],
            "applicability": {
                "status": record["applicability"].status.value,
                "reasons": list(record["applicability"].reasons),
            },
            "quality": {
                "semantic_truth": record["quality"].semantic_truth.value,
                "completeness": record["quality"].completeness.value,
                "relevance": record["quality"].relevance.value,
                "readiness": record["quality"].readiness.value,
                "reasons": list(record["quality"].reasons),
            },
            "canonical_fitness": {
                "status": fitness.status.value,
                "reasons": list(fitness.reasons),
                "authorizes_action": fitness.authorizes_action,
            },
            "review_route": _route(fitness.status),
            "lineage_evidence_refs": list(record["lineage_evidence_refs"]),
            "gate_evidence_refs": list(record["gate_evidence_refs"]),
            "acceptance_authority": False,
            "merge_authority": False,
            "close_authority": False,
            "execution_authority": False,
        }
        decision_records.append(decision)
        grouped[(record["lineage_root_id"], fitness.status.value)].append(decision)

    groups: list[dict[str, Any]] = []
    for (lineage_root_id, fitness_status), members in sorted(grouped.items()):
        member_identity = {
            "lineage_root_id": lineage_root_id,
            "fitness_status": fitness_status,
            "pack_ids": sorted(member["pack_id"] for member in members),
            "decision_ids": sorted(member["decision_id"] for member in members),
        }
        groups.append(
            {
                "group_id": _digest(member_identity),
                "lineage_root_id": lineage_root_id,
                "canonical_fitness_status": fitness_status,
                "group_size": len(members),
                "proposal_prs": sorted(member["proposal_pr"] for member in members),
                "pack_ids": sorted(member["pack_id"] for member in members),
                "decision_ids": sorted(member["decision_id"] for member in members),
                "scope": "REVIEW_ERGONOMICS_ONLY",
                "semantic_merge": False,
                "group_decision_authority": False,
            }
        )

    plan_identity = {
        "source_audit_digest": source_audit_digest,
        "current_main_revision": current_main_revision,
        "captured_at": captured_at.isoformat(),
        "decision_ids": sorted(item["decision_id"] for item in decision_records),
        "group_ids": sorted(item["group_id"] for item in groups),
    }

    return {
        "schema": RESULT_SCHEMA,
        "mode": "REVIEW_ADVISORY_ONLY",
        "synthetic": synthetic,
        "authority_granted": False,
        "merge_authority": False,
        "close_authority": False,
        "acceptance_authority": False,
        "execution_authority": False,
        "policy_mutation_authority": False,
        "source_audit_schema": SOURCE_AUDIT_SCHEMA,
        "source_audit_digest": source_audit_digest,
        "current_main_revision": current_main_revision,
        "captured_at": captured_at.isoformat(),
        "record_count": len(decision_records),
        "group_count": len(groups),
        "decisions": sorted(decision_records, key=lambda item: item["proposal_pr"]),
        "groups": groups,
        "invariants": [
            "one planner decision is preserved per Memory Pack",
            "grouping does not merge or deduplicate Memory Pack identity",
            "canonical CML information fitness is recomputed from supplied gate results",
            "review routing does not grant acceptance, merge, close, execution, or policy authority",
        ],
        "non_claims": [
            "shared lineage_root_id does not prove semantic duplication",
            "READY_FOR_AUTHORITY_CHECK does not authorize Memory Pack acceptance",
            "NOT_FIT does not authorize deletion or closure",
            "synthetic fixtures are conformance evidence only, not production queue outcomes",
        ],
        "plan_digest": _digest(plan_identity),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plan bounded review groups from CML memory proposal revalidation results"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        result = plan(payload)
    except (OSError, json.JSONDecodeError, QueuePlanningError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2

    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
