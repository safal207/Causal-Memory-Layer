from __future__ import annotations

import json
from pathlib import Path

import pytest

from cml.integrations.memory_pack import (
    MEMORY_PACK_SCHEMA,
    MemoryEdgeV1,
    MemoryEvidenceV1,
    MemoryGraphV1,
    MemoryNodeV1,
    MemoryPackManifestV1,
    MemoryPackV1,
    MemoryRedactionV1,
    canonical_memory_pack_json,
    derive_memory_pack_id,
    issue_memory_pack,
    load_memory_pack_json,
    memory_pack_from_mapping,
    verify_memory_pack,
)

COMMIT = "2b6d69540096b42313979dc8fcaed526caf14bd7"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def manifest(*, visibility: str = "public", private: bool = False):
    return MemoryPackManifestV1(
        project="Causal-Memory-Layer",
        source_repository="https://github.com/safal207/Causal-Memory-Layer",
        source_commit=COMMIT,
        created_at="2026-07-17T00:00:00.000Z",
        visibility=visibility,
        license="MIT",
        contains_private_data=private,
        merge_authority=False,
        execution_authority=False,
        description="Portable memory of a reviewer fallback decision cycle.",
    )


def evidence():
    return (
        MemoryEvidenceV1(
            id="commit-179",
            kind="commit",
            digest=DIGEST_A,
            locator=f"git:{COMMIT}",
            description="Merged recovery implementation.",
        ),
        MemoryEvidenceV1(
            id="ci-179",
            kind="workflow_run",
            digest=DIGEST_B,
            locator="github-actions:29537160971",
            description="Exact-head CI success.",
        ),
    )


def graph():
    return MemoryGraphV1(
        nodes=(
            MemoryNodeV1(
                id="outcome-recovery",
                kind="outcome",
                label="Protected reconciliation path merged",
                status="verified",
                confidence=95,
                attributes={"merge_commit": COMMIT},
            ),
            MemoryNodeV1(
                id="situation-missed-event",
                kind="situation",
                label="CodeRabbit rate-limit comment exists without fallback lifecycle",
                status="observed",
                confidence=100,
                attributes={"issue": 168},
            ),
            MemoryNodeV1(
                id="option-webhook-only",
                kind="option",
                label="Rely on native webhook delivery only",
                status="failed",
                confidence=100,
                attributes={"risk": "missed external event"},
            ),
            MemoryNodeV1(
                id="action-reconcile",
                kind="action",
                label="Add exact-head scheduled discovery and per-PR reconciliation",
                status="verified",
                confidence=95,
                attributes={"duplicate_policy": "noop"},
            ),
        ),
        edges=(
            MemoryEdgeV1(
                id="edge-selected",
                source="situation-missed-event",
                target="action-reconcile",
                relation="leads_to",
                strength=95,
                evidence_ids=("commit-179", "ci-179"),
            ),
            MemoryEdgeV1(
                id="edge-outcome",
                source="action-reconcile",
                target="outcome-recovery",
                relation="leads_to",
                strength=95,
                evidence_ids=("commit-179", "ci-179"),
            ),
            MemoryEdgeV1(
                id="edge-reject-webhook-only",
                source="action-reconcile",
                target="option-webhook-only",
                relation="selected_over",
                strength=90,
                evidence_ids=("commit-179",),
            ),
        ),
        selected_path=(
            "situation-missed-event",
            "action-reconcile",
            "outcome-recovery",
        ),
    )


def pack(*, visibility: str = "public", private: bool = False):
    return issue_memory_pack(
        manifest=manifest(visibility=visibility, private=private),
        graph=graph(),
        evidence=evidence(),
        redactions=(
            MemoryRedactionV1(
                path="graph.nodes[*].attributes.private_notes",
                reason="Private notes are excluded from the public projection.",
            ),
        ),
    )


def test_memory_pack_round_trip_and_identity_are_deterministic() -> None:
    original = pack()
    serialized = json.dumps(original.to_mapping(), ensure_ascii=False)
    loaded = load_memory_pack_json(serialized)

    assert loaded == original
    assert loaded.pack_id == derive_memory_pack_id(
        loaded.manifest, loaded.graph, loaded.evidence, loaded.redactions
    )
    assert loaded.same_authoritative_identity(original)
    assert verify_memory_pack(loaded).passed()
    assert original.schema_version == MEMORY_PACK_SCHEMA


def test_input_order_does_not_change_identity() -> None:
    first = issue_memory_pack(
        manifest=manifest(),
        graph=graph(),
        evidence=evidence(),
    )
    second = issue_memory_pack(
        manifest=manifest(),
        graph=MemoryGraphV1(
            nodes=tuple(reversed(graph().nodes)),
            edges=tuple(reversed(graph().edges)),
            selected_path=graph().selected_path,
        ),
        evidence=tuple(reversed(evidence())),
    )

    assert first.pack_id == second.pack_id
    assert canonical_memory_pack_json(
        first.manifest, first.graph, first.evidence, first.redactions
    ) == canonical_memory_pack_json(
        second.manifest, second.graph, second.evidence, second.redactions
    )


def test_authoritative_mutation_invalidates_pack_id() -> None:
    original = pack()
    payload = original.to_mapping()
    payload["graph"]["nodes"][0]["confidence"] = 1
    mutated = memory_pack_from_mapping(payload)

    result = verify_memory_pack(mutated)
    assert [finding.code for finding in result.findings] == [
        "CML-MEMORY-PACK-ID-MISMATCH"
    ]
    assert result.expected_pack_id != original.pack_id


def test_public_or_partner_private_data_fails_verification() -> None:
    for visibility in ("public", "partner"):
        unsafe_manifest = manifest(visibility=visibility, private=True)
        unsafe = MemoryPackV1(
            pack_id=derive_memory_pack_id(
                unsafe_manifest, graph(), evidence(), ()
            ),
            manifest=unsafe_manifest,
            graph=graph(),
            evidence=evidence(),
        )
        result = verify_memory_pack(unsafe)
        assert [finding.code for finding in result.findings] == [
            "CML-MEMORY-PACK-UNSAFE-SHARING"
        ]
        with pytest.raises(ValueError, match="CML-MEMORY-PACK-UNSAFE-SHARING"):
            issue_memory_pack(
                manifest=unsafe_manifest,
                graph=graph(),
                evidence=evidence(),
            )


def test_team_private_data_is_allowed_but_remains_declared() -> None:
    shared = pack(visibility="team", private=True)
    assert verify_memory_pack(shared).passed()
    assert shared.manifest.contains_private_data is True


def test_graph_rejects_dangling_edges_and_invalid_selected_path() -> None:
    with pytest.raises(ValueError, match="references a missing node"):
        MemoryGraphV1(
            nodes=graph().nodes,
            edges=(
                MemoryEdgeV1(
                    id="bad-edge",
                    source="situation-missed-event",
                    target="missing",
                    relation="leads_to",
                    strength=100,
                ),
            ),
            selected_path=("situation-missed-event", "outcome-recovery"),
        )

    with pytest.raises(ValueError, match="has no graph edge"):
        MemoryGraphV1(
            nodes=graph().nodes,
            edges=graph().edges,
            selected_path=("situation-missed-event", "outcome-recovery"),
        )


def test_duplicate_node_edge_evidence_and_redaction_ids_are_rejected() -> None:
    node = graph().nodes[0]
    with pytest.raises(ValueError, match="node ids must be unique"):
        MemoryGraphV1(
            nodes=(node, node),
            edges=(),
            selected_path=(node.id,),
        )

    with pytest.raises(ValueError, match="edge ids must be unique"):
        base = graph()
        MemoryGraphV1(
            nodes=base.nodes,
            edges=(base.edges[0], base.edges[0]),
            selected_path=base.selected_path,
        )

    with pytest.raises(ValueError, match="evidence ids must be unique"):
        item = evidence()[0]
        MemoryPackV1(
            pack_id="0" * 64,
            manifest=manifest(),
            graph=graph(),
            evidence=(item, item),
        )

    with pytest.raises(ValueError, match="redaction paths must be unique"):
        item = MemoryRedactionV1(path="x", reason="removed")
        MemoryPackV1(
            pack_id="0" * 64,
            manifest=manifest(),
            graph=graph(),
            evidence=evidence(),
            redactions=(item, item),
        )


def test_edge_evidence_must_exist() -> None:
    with pytest.raises(ValueError, match="references missing evidence"):
        issue_memory_pack(
            manifest=manifest(),
            graph=graph(),
            evidence=(evidence()[0],),
        )


def test_loader_rejects_duplicate_keys_and_unknown_fields() -> None:
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_memory_pack_json('{"schema_version":"x","schema_version":"y"}')

    payload = pack().to_mapping()
    payload["unexpected"] = True
    with pytest.raises(ValueError, match="unknown fields: unexpected"):
        memory_pack_from_mapping(payload)


def test_memory_pack_cannot_grant_merge_or_execution_authority() -> None:
    common = dict(
        project="Causal-Memory-Layer",
        source_repository="https://github.com/safal207/Causal-Memory-Layer",
        source_commit=COMMIT,
        created_at="2026-07-17T00:00:00.000Z",
        visibility="private",
        license="MIT",
        contains_private_data=False,
        description="Advisory memory only.",
    )
    with pytest.raises(ValueError, match="merge authority"):
        MemoryPackManifestV1(
            **common, merge_authority=True, execution_authority=False
        )
    with pytest.raises(ValueError, match="execution authority"):
        MemoryPackManifestV1(
            **common, merge_authority=False, execution_authority=True
        )


def test_evidence_digest_is_strict_sha256() -> None:
    with pytest.raises(ValueError, match="lowercase 64-character SHA-256"):
        MemoryEvidenceV1(
            id="bad",
            kind="test",
            digest="ABC",
            locator="test:x",
            description="Bad digest.",
        )


def test_public_example_is_valid_and_identity_bound() -> None:
    path = (
        Path(__file__).resolve().parents[1]
        / "examples/memory_packs/coderabbit_qodo_recovery_v1.json"
    )
    example = load_memory_pack_json(path.read_text(encoding="utf-8"))

    assert (
        example.pack_id
        == "931cd50e2d30e321f8327aea5487f579f7911f7a9ab5b306b343ba5512c13da4"
    )
    assert example.manifest.visibility == "public"
    assert example.manifest.contains_private_data is False
    assert example.graph.selected_path[0] == "situation-missed-review-event"
    assert example.graph.selected_path[-1] == "lesson-best-known-path"
    assert verify_memory_pack(example).passed()
