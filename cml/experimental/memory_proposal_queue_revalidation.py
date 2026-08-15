"""Evidence-bounded revalidation adapter for live CML Memory Proposals.

This module is deliberately pure: GitHub/network collection lives outside the
trust decision.  The adapter consumes trusted observations, reuses the existing
CML applicability + information-quality + information-fitness gates, and emits
one Planner v0.2 record per Memory Pack.

A structurally replayable Memory Pack is *not* treated as semantically accepted.
Independent semantic acceptance evidence is intentionally absent here, so the
quality gate remains REVIEW even when provenance replay succeeds.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from cml.integrations.information_fitness import evaluate_information_fitness
from cml.integrations.information_quality import (
    EvidenceBinding,
    InformationQualityObservation,
    evaluate_information_quality,
)
from cml.integrations.memory_applicability import (
    EnvironmentBinding,
    LineageDependency,
    SourceObservation,
    evaluate_memory_applicability,
)

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class QueueRevalidationError(ValueError):
    """Raised when a trusted collector observation is internally inconsistent."""


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise QueueRevalidationError(f"{field} must be a positive integer")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise QueueRevalidationError(f"{field} must be a non-empty string")
    return value.strip()


def _sha40(value: Any, field: str) -> str:
    text = _text(value, field)
    if not HEX40.fullmatch(text):
        raise QueueRevalidationError(f"{field} must be a lowercase 40-char Git SHA")
    return text


def _sha64(value: Any, field: str) -> str:
    text = _text(value, field)
    if not HEX64.fullmatch(text):
        raise QueueRevalidationError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise QueueRevalidationError(f"{field} must be boolean")
    return value


def _refs(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise QueueRevalidationError(f"{field} must be a non-empty list")
    refs = tuple(_text(item, f"{field} entry") for item in value)
    if len(refs) != len(set(refs)):
        raise QueueRevalidationError(f"{field} entries must be unique")
    return refs


def _digest(value: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_planner_record(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Convert one trusted live observation into a Planner v0.2 record.

    ``pack_id`` is the identity declared by the proposal queue.
    ``validated_pack_id`` is obtained by strict Memory Pack parsing.
    ``replayed_pack_id`` is rebuilt from the currently fetched authoritative
    source PR/files/reviews/check-runs using the source-owned learning core.

    The expected-vs-observed source digest used by the applicability gate is
    therefore the original deterministic pack identity vs the deterministic
    live replay identity.  Any source snapshot drift becomes DRIFT before review.
    """

    if not isinstance(observation, Mapping):
        raise QueueRevalidationError("observation must be an object")

    repository = _text(observation.get("repository"), "repository")
    if not REPOSITORY.fullmatch(repository):
        raise QueueRevalidationError("repository must be owner/name")

    proposal_pr = _positive_int(observation.get("proposal_pr"), "proposal_pr")
    source_pr = _positive_int(observation.get("source_pr"), "source_pr")
    source_merge = _sha40(observation.get("source_merge"), "source_merge")
    current_main_revision = _sha40(
        observation.get("current_main_revision"), "current_main_revision"
    )
    pack_id = _sha64(observation.get("pack_id"), "pack_id")
    validated_pack_id = _sha64(
        observation.get("validated_pack_id"), "validated_pack_id"
    )
    replayed_pack_id = _sha64(
        observation.get("replayed_pack_id"), "replayed_pack_id"
    )

    if validated_pack_id != pack_id:
        raise QueueRevalidationError(
            "validated Memory Pack identity contradicts proposal pack_id"
        )

    source_exists = _boolean(observation.get("source_exists"), "source_exists")
    source_ancestor_of_main = _boolean(
        observation.get("source_ancestor_of_main"), "source_ancestor_of_main"
    )
    evidence_refs = _refs(observation.get("evidence_refs"), "evidence_refs")

    source = SourceObservation(
        locator=f"https://github.com/{repository}/pull/{source_pr}",
        refetchable=True,
        exists=source_exists,
        expected_digest=pack_id,
        observed_digest=replayed_pack_id if source_exists else None,
    )
    stored_environment = EnvironmentBinding(
        repository=repository,
        branch="main",
        commit_sha=source_merge,
    )
    current_environment = EnvironmentBinding(
        repository=repository,
        branch="main",
        commit_sha=current_main_revision,
    )

    lineage = (
        LineageDependency(
            dependency_id=f"source-merge:{source_merge}",
            state="active" if source_ancestor_of_main else "superseded",
            expected_digest=pack_id,
            observed_digest=replayed_pack_id if source_exists else None,
        ),
    )

    # ``now`` is irrelevant unless a historical valid_until exists; none is
    # invented by this adapter.  Use a fixed timezone-aware value so the pure
    # result is deterministic for the same observation.
    from datetime import datetime, timezone

    applicability = evaluate_memory_applicability(
        source=source,
        stored_environment=stored_environment,
        current_environment=current_environment,
        now=datetime(2000, 1, 1, tzinfo=timezone.utc),
        lineage=lineage,
    )

    supporting: list[str] = ["pack-integrity"]
    contradicting: list[str] = []
    observed_aspects: list[str] = ["pack_identity"]

    if source_exists and replayed_pack_id == pack_id:
        supporting.append("source-replay")
        observed_aspects.append("source_replay")
    else:
        contradicting.append("source-replay-mismatch")

    if source_ancestor_of_main:
        supporting.append("main-ancestry")
        observed_aspects.append("current_main_ancestry")

    evidence_ids = tuple((*supporting, *contradicting))
    item_id = f"memory-pack:{pack_id}"
    source_record_id = f"proposal-pr:{proposal_pr}"
    bindings = tuple(
        EvidenceBinding(
            evidence_id=evidence_id,
            evaluated_item_id=item_id,
            source_record_id=source_record_id,
            accepted_state_token=current_main_revision,
        )
        for evidence_id in evidence_ids
    )

    quality = evaluate_information_quality(
        InformationQualityObservation(
            supporting_evidence=tuple(supporting),
            contradicting_evidence=tuple(contradicting),
            required_aspects=(
                "pack_identity",
                "source_replay",
                "current_main_ancestry",
                "semantic_acceptance",
            ),
            observed_aspects=tuple(observed_aspects),
            claim_aspects=(
                "pack_identity",
                "source_replay",
                "current_main_ancestry",
                "semantic_acceptance",
            ),
            evaluated_item_id=item_id,
            source_record_id=source_record_id,
            accepted_state_token=current_main_revision,
            evidence_bindings=bindings,
        )
    )
    fitness = evaluate_information_fitness(
        applicability=applicability,
        quality=quality,
    )

    # No shared lineage is inferred from similar templates or proximity.  A
    # later evidence-backed lineage pass may replace this per-source root.
    lineage_root_id = f"source-pr:{source_pr}"

    identity = {
        "proposal_pr": proposal_pr,
        "source_pr": source_pr,
        "source_merge": source_merge,
        "pack_id": pack_id,
        "current_main_revision": current_main_revision,
        "replayed_pack_id": replayed_pack_id,
        "source_ancestor_of_main": source_ancestor_of_main,
        "applicability": applicability.status.value,
        "quality": quality.readiness.value,
        "fitness": fitness.status.value,
    }

    return {
        "proposal_pr": proposal_pr,
        "source_pr": source_pr,
        "source_merge": source_merge,
        "pack_id": pack_id,
        "lineage_root_id": lineage_root_id,
        "lineage_evidence_refs": list(evidence_refs),
        "gate_evidence_refs": list(evidence_refs),
        "applicability": {
            "status": applicability.status.value,
            "reasons": list(applicability.reasons),
        },
        "quality": {
            "semantic_truth": quality.semantic_truth.value,
            "completeness": quality.completeness.value,
            "relevance": quality.relevance.value,
            "readiness": quality.readiness.value,
            "reasons": list(quality.reasons),
        },
        "claimed_fitness_status": fitness.status.value,
        "revalidation": {
            "validated_pack_id": validated_pack_id,
            "replayed_pack_id": replayed_pack_id,
            "source_exists": source_exists,
            "source_ancestor_of_main": source_ancestor_of_main,
            "semantic_acceptance_evidence": "NOT_COLLECTED",
            "observation_digest": _digest(identity),
        },
        "authority_granted": False,
        "merge_authority": False,
        "close_authority": False,
        "acceptance_authority": False,
        "execution_authority": False,
        "policy_mutation_authority": False,
    }
