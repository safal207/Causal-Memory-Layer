#!/usr/bin/env python3
"""Evidence-bound human semantic review intake for CML Memory Proposals.

v0.4 deliberately separates three things that are easy to conflate:

1. machine revalidation says what is structurally/currently known;
2. a frozen review packet says exactly what a human is being asked to judge;
3. a human verdict records semantic evidence but grants no repository authority.

Even ``ACCEPT`` only records semantic support for a later, separate authority
check. This module never merges, closes, accepts, rejects, rewrites, or executes
Memory Packs.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

PLANNER_INPUT_SCHEMA = "cml.memory-proposal-queue.revalidation-input.v0.2"
PLANNER_RESULT_SCHEMA = "cml.memory-proposal-queue.revalidation-plan.v0.2"
INTAKE_SCHEMA = "cml.memory-proposal-queue.semantic-acceptance-intake.v0.4"
SUBMISSION_SCHEMA = "cml.memory-proposal-queue.semantic-review-submission.v0.4"
RECORD_SCHEMA = "cml.memory-proposal-queue.semantic-review-record.v0.4"
SHA256_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_VERDICTS = ("ACCEPT", "REJECT", "DEFER")


class SemanticAcceptanceError(ValueError):
    """Raised when semantic-review evidence is incomplete or misbound."""


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SemanticAcceptanceError(f"{field} must be an object")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SemanticAcceptanceError(f"{field} must be a non-empty string")
    return value.strip()


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SemanticAcceptanceError(f"{field} must be a positive integer")
    return value


def _sha256_ref(value: Any, field: str) -> str:
    text = _text(value, field)
    if not SHA256_REF.fullmatch(text):
        raise SemanticAcceptanceError(f"{field} must be a sha256: digest")
    return text


def _sha40(value: Any, field: str) -> str:
    text = _text(value, field)
    if not HEX40.fullmatch(text):
        raise SemanticAcceptanceError(f"{field} must be a lowercase 40-char SHA")
    return text


def _sha64(value: Any, field: str) -> str:
    text = _text(value, field)
    if not HEX64.fullmatch(text):
        raise SemanticAcceptanceError(f"{field} must be a lowercase 64-char digest")
    return text


def _refs(value: Any, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise SemanticAcceptanceError(f"{field} must be a list")
    refs = tuple(_text(item, f"{field} entry") for item in value)
    if not allow_empty and not refs:
        raise SemanticAcceptanceError(f"{field} must not be empty")
    if len(refs) != len(set(refs)):
        raise SemanticAcceptanceError(f"{field} entries must be unique")
    return refs


def _parse_time(value: Any, field: str) -> datetime:
    text = _text(value, field)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SemanticAcceptanceError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise SemanticAcceptanceError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _digest(payload: Any) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _authority_false(payload: Mapping[str, Any], field: str) -> None:
    for key in (
        "authority_granted",
        "merge_authority",
        "close_authority",
        "acceptance_authority",
        "execution_authority",
        "policy_mutation_authority",
    ):
        if payload.get(key) is not False:
            raise SemanticAcceptanceError(f"{field}.{key} must be false")


def _review_requirement(fitness_status: str) -> tuple[str, bool]:
    if fitness_status == "REVIEW_REQUIRED":
        return "PENDING_HUMAN_SEMANTIC_REVIEW", True
    if fitness_status == "NOT_FIT":
        return "BLOCKED_PENDING_NEW_EVIDENCE_OR_CONTEXT", False
    if fitness_status == "READY_FOR_AUTHORITY_CHECK":
        return "SEPARATE_AUTHORITY_REVIEW_ONLY", False
    raise SemanticAcceptanceError(f"unsupported canonical fitness: {fitness_status}")


def build_semantic_acceptance_intake(
    planner_input: Mapping[str, Any],
    planner_result: Mapping[str, Any],
) -> dict[str, Any]:
    """Freeze one human-review packet per planner decision.

    The packet binds the human judgment to a specific machine observation and
    current-main revision. It is review input only, never acceptance authority.
    """

    planner_input = _mapping(planner_input, "planner_input")
    planner_result = _mapping(planner_result, "planner_result")
    if planner_input.get("schema") != PLANNER_INPUT_SCHEMA:
        raise SemanticAcceptanceError(
            f"planner_input.schema must be {PLANNER_INPUT_SCHEMA}"
        )
    if planner_result.get("schema") != PLANNER_RESULT_SCHEMA:
        raise SemanticAcceptanceError(
            f"planner_result.schema must be {PLANNER_RESULT_SCHEMA}"
        )
    _authority_false(planner_result, "planner_result")

    current_main = _sha40(
        planner_input.get("current_main_revision"),
        "planner_input.current_main_revision",
    )
    if planner_result.get("current_main_revision") != current_main:
        raise SemanticAcceptanceError("planner input/result current main mismatch")

    source_plan_digest = _sha256_ref(
        planner_result.get("plan_digest"), "planner_result.plan_digest"
    )
    source_audit_digest = _sha256_ref(
        planner_input.get("source_audit_digest"), "planner_input.source_audit_digest"
    )
    captured_at = _parse_time(planner_input.get("captured_at"), "captured_at")

    records_raw = planner_input.get("records")
    decisions_raw = planner_result.get("decisions")
    if not isinstance(records_raw, list) or not records_raw:
        raise SemanticAcceptanceError("planner_input.records must be a non-empty list")
    if not isinstance(decisions_raw, list) or not decisions_raw:
        raise SemanticAcceptanceError("planner_result.decisions must be a non-empty list")
    if len(records_raw) != len(decisions_raw):
        raise SemanticAcceptanceError("planner input/result record coverage mismatch")
    if planner_result.get("record_count") != len(decisions_raw):
        raise SemanticAcceptanceError("planner_result.record_count is inconsistent")

    records: dict[int, Mapping[str, Any]] = {}
    for raw in records_raw:
        record = _mapping(raw, "planner record")
        proposal_pr = _positive_int(record.get("proposal_pr"), "record.proposal_pr")
        if proposal_pr in records:
            raise SemanticAcceptanceError(f"duplicate planner record #{proposal_pr}")
        records[proposal_pr] = record

    packets: list[dict[str, Any]] = []
    seen_packet_ids: set[str] = set()
    pending_count = 0
    blocked_count = 0
    authority_only_count = 0

    for raw in decisions_raw:
        decision = _mapping(raw, "planner decision")
        proposal_pr = _positive_int(decision.get("proposal_pr"), "decision.proposal_pr")
        record = records.get(proposal_pr)
        if record is None:
            raise SemanticAcceptanceError(
                f"planner decision #{proposal_pr} has no matching input record"
            )

        decision_id = _sha256_ref(decision.get("decision_id"), "decision.decision_id")
        pack_id = _sha64(decision.get("pack_id"), "decision.pack_id")
        source_pr = _positive_int(decision.get("source_pr"), "decision.source_pr")
        source_merge = _sha40(decision.get("source_merge"), "decision.source_merge")
        if record.get("pack_id") != pack_id:
            raise SemanticAcceptanceError(f"proposal #{proposal_pr} pack mismatch")
        if record.get("source_pr") != source_pr:
            raise SemanticAcceptanceError(f"proposal #{proposal_pr} source PR mismatch")
        if record.get("source_merge") != source_merge:
            raise SemanticAcceptanceError(f"proposal #{proposal_pr} source merge mismatch")

        revalidation = _mapping(record.get("revalidation"), "record.revalidation")
        observation_digest = _sha256_ref(
            revalidation.get("observation_digest"),
            "record.revalidation.observation_digest",
        )
        stable_match = revalidation.get("stable_source_core_match")
        ancestor = revalidation.get("source_ancestor_of_main")
        if not isinstance(stable_match, bool) or not isinstance(ancestor, bool):
            raise SemanticAcceptanceError("revalidation stable/ancestry flags must be boolean")
        changed_components = _refs(
            revalidation.get("changed_evidence_components"),
            "record.revalidation.changed_evidence_components",
            allow_empty=True,
        )

        applicability = _mapping(decision.get("applicability"), "decision.applicability")
        quality = _mapping(decision.get("quality"), "decision.quality")
        fitness = _mapping(decision.get("canonical_fitness"), "decision.canonical_fitness")
        fitness_status = _text(fitness.get("status"), "decision.canonical_fitness.status")
        packet_status, human_review_required = _review_requirement(fitness_status)
        if packet_status == "PENDING_HUMAN_SEMANTIC_REVIEW":
            pending_count += 1
        elif packet_status == "BLOCKED_PENDING_NEW_EVIDENCE_OR_CONTEXT":
            blocked_count += 1
        else:
            authority_only_count += 1

        gate_refs = _refs(decision.get("gate_evidence_refs"), "decision.gate_evidence_refs")
        lineage_refs = _refs(
            decision.get("lineage_evidence_refs"), "decision.lineage_evidence_refs"
        )
        packet_identity = {
            "decision_id": decision_id,
            "proposal_pr": proposal_pr,
            "source_pr": source_pr,
            "source_merge": source_merge,
            "pack_id": pack_id,
            "current_main_revision": current_main,
            "observation_digest": observation_digest,
            "gate_evidence_refs": sorted(gate_refs),
            "lineage_evidence_refs": sorted(lineage_refs),
        }
        packet_id = _digest(packet_identity)
        if packet_id in seen_packet_ids:
            raise SemanticAcceptanceError("duplicate semantic review packet identity")
        seen_packet_ids.add(packet_id)

        packet = {
            "packet_id": packet_id,
            "status": packet_status,
            "human_review_required": human_review_required,
            "decision_id": decision_id,
            "proposal_pr": proposal_pr,
            "source_pr": source_pr,
            "source_merge": source_merge,
            "pack_id": pack_id,
            "current_main_revision": current_main,
            "observation_digest": observation_digest,
            "machine_gate": {
                "applicability_status": _text(
                    applicability.get("status"), "decision.applicability.status"
                ),
                "quality_readiness": _text(
                    quality.get("readiness"), "decision.quality.readiness"
                ),
                "canonical_fitness_status": fitness_status,
                "review_route": _text(decision.get("review_route"), "decision.review_route"),
                "stable_source_core_match": stable_match,
                "source_ancestor_of_main": ancestor,
                "changed_evidence_components": sorted(changed_components),
            },
            "gate_evidence_refs": list(gate_refs),
            "lineage_evidence_refs": list(lineage_refs),
            "allowed_human_verdicts": list(ALLOWED_VERDICTS),
            "submission_contract": {
                "reviewer_id_required": True,
                "reviewed_at_required": True,
                "rationale_required": True,
                "reviewed_gate_evidence_refs_must_match_packet": True,
                "observed_main_revision_must_match_packet": True,
                "additional_evidence_refs_optional": True,
            },
            "authority_granted": False,
            "merge_authority": False,
            "close_authority": False,
            "acceptance_authority": False,
            "execution_authority": False,
            "policy_mutation_authority": False,
        }
        packets.append(packet)

    intake_identity = {
        "source_plan_digest": source_plan_digest,
        "source_audit_digest": source_audit_digest,
        "current_main_revision": current_main,
        "captured_at": captured_at.isoformat(),
        "packet_ids": sorted(packet["packet_id"] for packet in packets),
    }
    return {
        "schema": INTAKE_SCHEMA,
        "mode": "HUMAN_SEMANTIC_REVIEW_INTAKE_ONLY",
        "source_plan_digest": source_plan_digest,
        "source_audit_digest": source_audit_digest,
        "current_main_revision": current_main,
        "captured_at": captured_at.isoformat(),
        "packet_count": len(packets),
        "pending_human_review_count": pending_count,
        "blocked_pending_evidence_count": blocked_count,
        "separate_authority_review_only_count": authority_only_count,
        "completed_human_review_count": 0,
        "packets": sorted(packets, key=lambda item: item["proposal_pr"]),
        "authority_granted": False,
        "merge_authority": False,
        "close_authority": False,
        "acceptance_authority": False,
        "execution_authority": False,
        "policy_mutation_authority": False,
        "invariants": [
            "one semantic review packet is preserved per planner decision",
            "a packet binds human review to exact machine evidence and current main",
            "human ACCEPT records semantic support but does not accept a Memory Pack",
            "human REJECT records semantic rejection but does not close or delete a proposal",
            "human DEFER records no semantic conclusion",
        ],
        "intake_digest": _digest(intake_identity),
    }


def validate_human_submission(
    intake: Mapping[str, Any], submission: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate one human verdict against a frozen v0.4 packet.

    The returned record is evidence only. No verdict grants repository authority.
    """

    intake = _mapping(intake, "intake")
    submission = _mapping(submission, "submission")
    if intake.get("schema") != INTAKE_SCHEMA:
        raise SemanticAcceptanceError(f"intake.schema must be {INTAKE_SCHEMA}")
    _authority_false(intake, "intake")
    if submission.get("schema") != SUBMISSION_SCHEMA:
        raise SemanticAcceptanceError(
            f"submission.schema must be {SUBMISSION_SCHEMA}"
        )

    packet_id = _sha256_ref(submission.get("packet_id"), "submission.packet_id")
    packets_raw = intake.get("packets")
    if not isinstance(packets_raw, list):
        raise SemanticAcceptanceError("intake.packets must be a list")
    matches = [
        packet
        for packet in packets_raw
        if isinstance(packet, Mapping) and packet.get("packet_id") == packet_id
    ]
    if len(matches) != 1:
        raise SemanticAcceptanceError("submission packet_id is not uniquely present")
    packet = matches[0]
    if packet.get("human_review_required") is not True:
        raise SemanticAcceptanceError("packet is not eligible for human semantic review")
    _authority_false(packet, "packet")

    decision_id = _sha256_ref(submission.get("decision_id"), "submission.decision_id")
    pack_id = _sha64(submission.get("pack_id"), "submission.pack_id")
    observed_main = _sha40(
        submission.get("observed_main_revision"), "submission.observed_main_revision"
    )
    if decision_id != packet.get("decision_id"):
        raise SemanticAcceptanceError("submission decision_id does not match packet")
    if pack_id != packet.get("pack_id"):
        raise SemanticAcceptanceError("submission pack_id does not match packet")
    if observed_main != packet.get("current_main_revision"):
        raise SemanticAcceptanceError("submission current main is stale or misbound")

    reviewer_id = _text(submission.get("reviewer_id"), "submission.reviewer_id")
    reviewed_at = _parse_time(submission.get("reviewed_at"), "submission.reviewed_at")
    verdict = _text(submission.get("verdict"), "submission.verdict")
    if verdict not in ALLOWED_VERDICTS:
        raise SemanticAcceptanceError(
            "submission.verdict must be one of: " + ", ".join(ALLOWED_VERDICTS)
        )
    rationale = _text(submission.get("rationale"), "submission.rationale")
    reviewed_gate_refs = _refs(
        submission.get("reviewed_gate_evidence_refs"),
        "submission.reviewed_gate_evidence_refs",
    )
    packet_gate_refs = _refs(packet.get("gate_evidence_refs"), "packet.gate_evidence_refs")
    if sorted(reviewed_gate_refs) != sorted(packet_gate_refs):
        raise SemanticAcceptanceError(
            "reviewed gate evidence refs must exactly match the frozen packet"
        )
    additional_refs = _refs(
        submission.get("additional_evidence_refs", []),
        "submission.additional_evidence_refs",
        allow_empty=True,
    )

    if verdict == "ACCEPT":
        next_route = "SEPARATE_ACCEPTANCE_AUTHORITY_CHECK_REQUIRED"
        semantic_effect = "SEMANTIC_SUPPORT_RECORDED"
    elif verdict == "REJECT":
        next_route = "SEPARATE_REJECTION_OR_CLOSURE_AUTHORITY_CHECK_REQUIRED"
        semantic_effect = "SEMANTIC_REJECTION_RECORDED"
    else:
        next_route = "AWAIT_NEW_EVIDENCE_OR_FURTHER_HUMAN_REVIEW"
        semantic_effect = "SEMANTIC_REVIEW_DEFERRED"

    record_identity = {
        "packet_id": packet_id,
        "decision_id": decision_id,
        "pack_id": pack_id,
        "observed_main_revision": observed_main,
        "reviewer_id": reviewer_id,
        "reviewed_at": reviewed_at.isoformat(),
        "verdict": verdict,
        "rationale": rationale,
        "reviewed_gate_evidence_refs": sorted(reviewed_gate_refs),
        "additional_evidence_refs": sorted(additional_refs),
    }
    return {
        "schema": RECORD_SCHEMA,
        "record_id": _digest(record_identity),
        "packet_id": packet_id,
        "decision_id": decision_id,
        "proposal_pr": packet.get("proposal_pr"),
        "source_pr": packet.get("source_pr"),
        "source_merge": packet.get("source_merge"),
        "pack_id": pack_id,
        "observed_main_revision": observed_main,
        "observation_digest": packet.get("observation_digest"),
        "reviewer_id": reviewer_id,
        "reviewed_at": reviewed_at.isoformat(),
        "verdict": verdict,
        "rationale": rationale,
        "reviewed_gate_evidence_refs": list(reviewed_gate_refs),
        "additional_evidence_refs": list(additional_refs),
        "semantic_effect": semantic_effect,
        "next_route": next_route,
        "state_mutation_performed": False,
        "authority_granted": False,
        "merge_authority": False,
        "close_authority": False,
        "acceptance_authority": False,
        "execution_authority": False,
        "policy_mutation_authority": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="build semantic review intake")
    build.add_argument("planner_input", type=Path)
    build.add_argument("planner_result", type=Path)

    validate = sub.add_parser("validate", help="validate one human review submission")
    validate.add_argument("intake", type=Path)
    validate.add_argument("submission", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "build":
            planner_input = json.loads(args.planner_input.read_text(encoding="utf-8"))
            planner_result = json.loads(args.planner_result.read_text(encoding="utf-8"))
            result = build_semantic_acceptance_intake(planner_input, planner_result)
        else:
            intake = json.loads(args.intake.read_text(encoding="utf-8"))
            submission = json.loads(args.submission.read_text(encoding="utf-8"))
            result = validate_human_submission(intake, submission)
    except (OSError, json.JSONDecodeError, SemanticAcceptanceError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2

    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
