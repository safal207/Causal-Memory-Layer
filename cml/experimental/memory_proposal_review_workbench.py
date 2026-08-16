#!/usr/bin/env python3
"""Deterministic Human Review Workbench for CML Memory Proposals.

v0.5 turns frozen v0.4 semantic-review packets into a bounded review queue.
It does not score truth, accept Memory Packs, or mutate repository state.
Priority is lexicographic over observed review effort/risk signals:

1. source scope missing on current main;
2. source scope diverged on current main;
3. descriptive/review context changed;
4. operational evidence changed;
5. source scope currently matches the source-merge snapshot.

Within a class, lower generated-lesson confidence, broader source scope, and
older source merge timestamps are reviewed first. These are review-order
heuristics only, never semantic or authority verdicts.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from cml.experimental.memory_proposal_semantic_acceptance import (
    INTAKE_SCHEMA,
    SemanticAcceptanceError,
    verify_semantic_acceptance_intake,
)

CONTEXT_SCHEMA = "cml.memory-proposal-queue.review-contexts.v0.5"
WORKBENCH_SCHEMA = "cml.memory-proposal-queue.human-review-workbench.v0.5"
SUBMISSION_SCHEMA = "cml.memory-proposal-queue.semantic-review-submission.v0.4"

PATH_SAME = "SAME_AS_SOURCE_MERGE"
PATH_DIVERGED = "DIVERGED_FROM_SOURCE_MERGE"
PATH_MISSING = "MISSING_OR_RENAMED_ON_CURRENT_MAIN"
ALLOWED_PATH_STATES = (PATH_SAME, PATH_DIVERGED, PATH_MISSING)


class ReviewWorkbenchError(ValueError):
    """Raised when workbench context is incomplete, stale, or misbound."""


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReviewWorkbenchError(f"{field} must be an object")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewWorkbenchError(f"{field} must be a non-empty string")
    return value.strip()


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReviewWorkbenchError(f"{field} must be a positive integer")
    return value


def _confidence(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise ReviewWorkbenchError(f"{field} must be an integer in [0, 100]")
    return value


def _parse_time(value: Any, field: str) -> datetime:
    text = _text(value, field)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ReviewWorkbenchError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ReviewWorkbenchError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _strings(value: Any, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ReviewWorkbenchError(f"{field} must be a list")
    items = tuple(_text(item, f"{field} entry") for item in value)
    if not allow_empty and not items:
        raise ReviewWorkbenchError(f"{field} must not be empty")
    if len(items) != len(set(items)):
        raise ReviewWorkbenchError(f"{field} entries must be unique")
    return items


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
            raise ReviewWorkbenchError(f"{field}.{key} must be false")


def _path_state(raw: Any, proposal_pr: int) -> dict[str, Any]:
    item = _mapping(raw, f"proposal {proposal_pr}.path_state")
    path = _text(item.get("path"), f"proposal {proposal_pr}.path_state.path")
    status = _text(item.get("status"), f"proposal {proposal_pr}.path_state.status")
    if status not in ALLOWED_PATH_STATES:
        raise ReviewWorkbenchError(
            f"proposal {proposal_pr}.path_state.status must be one of: "
            + ", ".join(ALLOWED_PATH_STATES)
        )
    source_blob = _text(
        item.get("source_blob_sha"), f"proposal {proposal_pr}.path_state.source_blob_sha"
    )
    current_blob = item.get("current_blob_sha")
    if status == PATH_MISSING:
        if current_blob is not None:
            raise ReviewWorkbenchError(
                f"proposal {proposal_pr} missing path cannot have current_blob_sha"
            )
    else:
        current_blob = _text(
            current_blob, f"proposal {proposal_pr}.path_state.current_blob_sha"
        )
        if status == PATH_SAME and current_blob != source_blob:
            raise ReviewWorkbenchError(
                f"proposal {proposal_pr} SAME path must preserve blob identity"
            )
        if status == PATH_DIVERGED and current_blob == source_blob:
            raise ReviewWorkbenchError(
                f"proposal {proposal_pr} DIVERGED path must change blob identity"
            )
    return {
        "path": path,
        "status": status,
        "source_blob_sha": source_blob,
        "current_blob_sha": current_blob,
    }


def _priority_class(packet: Mapping[str, Any], context: Mapping[str, Any]) -> tuple[int, str]:
    path_states = context["path_states"]
    statuses = {item["status"] for item in path_states}
    changed = set(packet["machine_gate"]["changed_evidence_components"])
    if PATH_MISSING in statuses:
        return 0, "P0_SOURCE_SCOPE_MISSING"
    if PATH_DIVERGED in statuses:
        return 1, "P1_SOURCE_SCOPE_DIVERGED"
    if changed.intersection({"source-pr", "source-reviews"}):
        return 2, "P2_REVIEW_CONTEXT_DRIFT"
    if changed.intersection({"source-checks"}):
        return 3, "P3_OPERATIONAL_EVIDENCE_REFRESH"
    return 4, "P4_CURRENT_SCOPE_MATCH"


def build_review_workbench(
    intake: Mapping[str, Any],
    contexts_payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a deterministic review queue from frozen intake + live context."""

    intake = _mapping(intake, "intake")
    contexts_payload = _mapping(contexts_payload, "contexts_payload")
    if intake.get("schema") != INTAKE_SCHEMA:
        raise ReviewWorkbenchError(f"intake.schema must be {INTAKE_SCHEMA}")
    if contexts_payload.get("schema") != CONTEXT_SCHEMA:
        raise ReviewWorkbenchError(f"contexts_payload.schema must be {CONTEXT_SCHEMA}")
    _authority_false(intake, "intake")
    try:
        intake_digest = verify_semantic_acceptance_intake(intake)
    except SemanticAcceptanceError as exc:
        raise ReviewWorkbenchError(f"frozen semantic intake is invalid: {exc}") from exc

    current_main = _text(intake.get("current_main_revision"), "intake.current_main_revision")
    if contexts_payload.get("current_main_revision") != current_main:
        raise ReviewWorkbenchError("review contexts are stale or bound to a different main")
    if contexts_payload.get("source_intake_digest") != intake_digest:
        raise ReviewWorkbenchError("review contexts do not bind the frozen intake")

    packets_raw = intake.get("packets")
    contexts_raw = contexts_payload.get("contexts")
    if not isinstance(packets_raw, list) or not packets_raw:
        raise ReviewWorkbenchError("intake.packets must be a non-empty list")
    if not isinstance(contexts_raw, list) or not contexts_raw:
        raise ReviewWorkbenchError("contexts_payload.contexts must be a non-empty list")
    if len(packets_raw) != len(contexts_raw):
        raise ReviewWorkbenchError("workbench context coverage must equal packet coverage")

    packets: dict[str, Mapping[str, Any]] = {}
    for raw in packets_raw:
        packet = _mapping(raw, "packet")
        _authority_false(packet, "packet")
        packet_id = _text(packet.get("packet_id"), "packet.packet_id")
        if packet_id in packets:
            raise ReviewWorkbenchError("duplicate packet_id in intake")
        packets[packet_id] = packet

    contexts: dict[str, dict[str, Any]] = {}
    for raw in contexts_raw:
        context = _mapping(raw, "review context")
        packet_id = _text(context.get("packet_id"), "context.packet_id")
        if packet_id in contexts:
            raise ReviewWorkbenchError("duplicate packet_id in review contexts")
        packet = packets.get(packet_id)
        if packet is None:
            raise ReviewWorkbenchError("review context references an unknown packet")
        proposal_pr = _positive_int(context.get("proposal_pr"), "context.proposal_pr")
        if proposal_pr != packet.get("proposal_pr"):
            raise ReviewWorkbenchError(f"proposal #{proposal_pr} context/packet mismatch")
        if context.get("pack_id") != packet.get("pack_id"):
            raise ReviewWorkbenchError(f"proposal #{proposal_pr} context pack mismatch")
        if context.get("decision_id") != packet.get("decision_id"):
            raise ReviewWorkbenchError(f"proposal #{proposal_pr} context decision mismatch")
        if context.get("current_main_revision") != current_main:
            raise ReviewWorkbenchError(f"proposal #{proposal_pr} context main mismatch")

        path_states_raw = context.get("path_states")
        if not isinstance(path_states_raw, list) or not path_states_raw:
            raise ReviewWorkbenchError(f"proposal #{proposal_pr} path_states must be non-empty")
        path_states = [_path_state(item, proposal_pr) for item in path_states_raw]
        paths = [item["path"] for item in path_states]
        if len(paths) != len(set(paths)):
            raise ReviewWorkbenchError(f"proposal #{proposal_pr} duplicate source path")

        lesson_confidence = _confidence(
            context.get("lesson_confidence"), f"proposal {proposal_pr}.lesson_confidence"
        )
        created_at = _parse_time(context.get("pack_created_at"), "context.pack_created_at")
        context_refs = _strings(
            context.get("context_evidence_refs"), "context.context_evidence_refs"
        )
        normalized = {
            "packet_id": packet_id,
            "proposal_pr": proposal_pr,
            "source_pr": _positive_int(context.get("source_pr"), "context.source_pr"),
            "pack_id": _text(context.get("pack_id"), "context.pack_id"),
            "decision_id": _text(context.get("decision_id"), "context.decision_id"),
            "current_main_revision": current_main,
            "source_title": _text(context.get("source_title"), "context.source_title"),
            "situation_label": _text(
                context.get("situation_label"), "context.situation_label"
            ),
            "action_label": _text(context.get("action_label"), "context.action_label"),
            "lesson_label": _text(context.get("lesson_label"), "context.lesson_label"),
            "lesson_confidence": lesson_confidence,
            "pack_created_at": created_at,
            "path_states": path_states,
            "context_evidence_refs": context_refs,
        }
        contexts[packet_id] = normalized

    if set(contexts) != set(packets):
        raise ReviewWorkbenchError("review context packet set must exactly match intake")

    sortable: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    for packet_id, packet in packets.items():
        context = contexts[packet_id]
        machine_gate = _mapping(packet.get("machine_gate"), "packet.machine_gate")
        changed_components = _strings(
            machine_gate.get("changed_evidence_components"),
            "packet.machine_gate.changed_evidence_components",
            allow_empty=True,
        )
        priority_packet = {
            "machine_gate": {"changed_evidence_components": changed_components}
        }
        priority_index, priority_class = _priority_class(priority_packet, context)
        missing_paths = [
            item["path"] for item in context["path_states"] if item["status"] == PATH_MISSING
        ]
        diverged_paths = [
            item["path"]
            for item in context["path_states"]
            if item["status"] == PATH_DIVERGED
        ]
        same_paths = [
            item["path"] for item in context["path_states"] if item["status"] == PATH_SAME
        ]

        queue_identity = {
            "packet_id": packet_id,
            "current_main_revision": current_main,
            "priority_class": priority_class,
            "lesson_label": context["lesson_label"],
            "path_states": context["path_states"],
            "changed_evidence_components": sorted(changed_components),
        }
        card = {
            "card_id": _digest(queue_identity),
            "packet_id": packet_id,
            "decision_id": packet.get("decision_id"),
            "proposal_pr": packet.get("proposal_pr"),
            "source_pr": packet.get("source_pr"),
            "pack_id": packet.get("pack_id"),
            "current_main_revision": current_main,
            "priority_class": priority_class,
            "review_reason": {
                "missing_or_renamed_paths": sorted(missing_paths),
                "diverged_paths": sorted(diverged_paths),
                "same_as_source_paths": sorted(same_paths),
                "changed_evidence_components": sorted(changed_components),
            },
            "review_context": {
                "source_title": context["source_title"],
                "situation": context["situation_label"],
                "action": context["action_label"],
                "lesson": context["lesson_label"],
                "lesson_confidence": context["lesson_confidence"],
                "pack_created_at": context["pack_created_at"].isoformat(),
                "source_path_count": len(context["path_states"]),
                "path_states": context["path_states"],
            },
            "machine_gate": dict(machine_gate),
            "gate_evidence_refs": list(packet.get("gate_evidence_refs", [])),
            "lineage_evidence_refs": list(packet.get("lineage_evidence_refs", [])),
            "context_evidence_refs": list(context["context_evidence_refs"]),
            "allowed_human_verdicts": list(packet.get("allowed_human_verdicts", [])),
            "submission_template": {
                "schema": SUBMISSION_SCHEMA,
                "packet_id": packet_id,
                "decision_id": packet.get("decision_id"),
                "pack_id": packet.get("pack_id"),
                "observed_main_revision": current_main,
                "reviewer_id": None,
                "reviewed_at": None,
                "verdict": None,
                "rationale": None,
                "reviewed_gate_evidence_refs": list(packet.get("gate_evidence_refs", [])),
                "additional_evidence_refs": [],
            },
            "review_completed": False,
            "authority_granted": False,
            "merge_authority": False,
            "close_authority": False,
            "acceptance_authority": False,
            "execution_authority": False,
            "policy_mutation_authority": False,
        }
        sort_key = (
            priority_index,
            context["lesson_confidence"],
            -len(context["path_states"]),
            context["pack_created_at"],
            int(packet.get("proposal_pr")),
        )
        sortable.append((sort_key, card))

    sortable.sort(key=lambda item: item[0])
    cards: list[dict[str, Any]] = []
    priority_counts: dict[str, int] = {}
    for rank, (_, card) in enumerate(sortable, start=1):
        card["queue_rank"] = rank
        cards.append(card)
        key = card["priority_class"]
        priority_counts[key] = priority_counts.get(key, 0) + 1

    workbench_identity = {
        "source_intake_digest": intake_digest,
        "current_main_revision": current_main,
        "card_ids": [card["card_id"] for card in cards],
    }
    return {
        "schema": WORKBENCH_SCHEMA,
        "mode": "HUMAN_REVIEW_WORKBENCH_ONLY",
        "source_intake_digest": intake_digest,
        "current_main_revision": current_main,
        "card_count": len(cards),
        "pending_review_count": len(cards),
        "completed_review_count": 0,
        "priority_class_counts": dict(sorted(priority_counts.items())),
        "cards": cards,
        "authority_granted": False,
        "merge_authority": False,
        "close_authority": False,
        "acceptance_authority": False,
        "execution_authority": False,
        "policy_mutation_authority": False,
        "invariants": [
            "one review card is preserved per frozen semantic packet",
            "queue priority orders human attention and does not score truth",
            "current path state is a net current-main comparison, not proof of historical touches",
            "submission templates are intentionally incomplete until a human supplies identity, time, verdict, and rationale",
            "workbench output grants no acceptance, merge, close, execution, or policy authority",
        ],
        "non_claims": [
            "a higher queue rank does not mean a Memory Pack is more correct or more important",
            "a current blob match does not prove the path was never changed and reverted",
            "source-path divergence does not prove the stored lesson is invalid",
            "an ACCEPT template or human verdict does not itself accept a Memory Pack",
        ],
        "workbench_digest": _digest(workbench_identity),
    }


def _inline(value: Any) -> str:
    """Flatten untrusted text to a single Markdown-safe inline fragment."""

    text = " ".join(str(value).split())
    for char in ("\\", "`", "*", "_", "#", "[", "]", "<", ">", "|"):
        text = text.replace(char, "\\" + char)
    return text


def render_markdown(workbench: Mapping[str, Any]) -> str:
    """Render a compact human-facing queue without inventing verdicts."""

    workbench = _mapping(workbench, "workbench")
    if workbench.get("schema") != WORKBENCH_SCHEMA:
        raise ReviewWorkbenchError(f"workbench.schema must be {WORKBENCH_SCHEMA}")
    cards = workbench.get("cards")
    if not isinstance(cards, list):
        raise ReviewWorkbenchError("workbench.cards must be a list")

    lines = [
        "# CML Human Review Workbench v0.5",
        "",
        f"Current main: `{workbench.get('current_main_revision')}`",
        f"Pending cards: **{workbench.get('pending_review_count')}**",
        "",
        "> Queue rank orders review attention only. It is not a truth or authority score.",
        "",
    ]
    for card in cards:
        context = card["review_context"]
        reason = card["review_reason"]
        lines.extend(
            [
                f"## {card['queue_rank']}. PR #{card['proposal_pr']} ← source #{card['source_pr']}",
                "",
                f"**Priority:** `{card['priority_class']}`",
                f"**Lesson:** {_inline(context['lesson'])}",
                f"**Situation:** {_inline(context['situation'])}",
                f"**Action:** {_inline(context['action'])}",
                f"**Source title:** {_inline(context['source_title'])}",
                f"**Generated lesson confidence:** {context['lesson_confidence']}/100",
                f"**Path state:** {len(reason['missing_or_renamed_paths'])} missing/renamed, "
                f"{len(reason['diverged_paths'])} diverged, "
                f"{len(reason['same_as_source_paths'])} same",
                "**Evidence drift:** "
                + (
                    ", ".join(_inline(item) for item in reason["changed_evidence_components"])
                    or "none observed"
                ),
                f"**Packet:** `{card['packet_id']}`",
                "",
                "Human action: inspect the frozen evidence, then fill `reviewer_id`, "
                "`reviewed_at`, `verdict`, and `rationale` in the bound submission template.",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build CML Human Review Workbench v0.5")
    parser.add_argument("intake", type=Path)
    parser.add_argument("contexts", type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()
    try:
        intake = json.loads(args.intake.read_text(encoding="utf-8"))
        contexts = json.loads(args.contexts.read_text(encoding="utf-8"))
        result = build_review_workbench(intake, contexts)
        if args.markdown is not None:
            args.markdown.write_text(render_markdown(result), encoding="utf-8")
    except (OSError, json.JSONDecodeError, ReviewWorkbenchError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
