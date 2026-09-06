from __future__ import annotations

from pathlib import Path

from cml.integrations.memory_pack import (
    derive_memory_pack_id,
    load_memory_pack_json,
    verify_memory_pack,
)


PACK_PATH = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "memory_packs"
    / "tradernet_product_funnel_audit_v1.json"
)


def test_tradernet_product_funnel_memory_pack_is_canonical() -> None:
    pack = load_memory_pack_json(PACK_PATH.read_text(encoding="utf-8"))

    result = verify_memory_pack(pack)
    assert result.passed(), result.findings
    assert pack.pack_id == derive_memory_pack_id(
        pack.manifest,
        pack.graph,
        pack.evidence,
        pack.redactions,
    )
    assert pack.pack_id == (
        "d9b886e7b4985dd9c4932232a69a5bfb5caaf70f597051a87dd93357560c4654"
    )


def test_pack_preserves_product_hypotheses_as_unproven() -> None:
    pack = load_memory_pack_json(PACK_PATH.read_text(encoding="utf-8"))
    nodes = {node.id: node for node in pack.graph.nodes}

    constraint = nodes["constraint-authenticated-journeys-unproven"]
    assert constraint.status == "verified"
    assert constraint.attributes["defect_claim_allowed"] is False
    assert constraint.attributes["source_judgment"] == "ESCALATE"
    assert tuple(constraint.attributes["required_labels"]) == (
        "HYPOTHESIS",
        "NEEDS_AUTHENTICATED_EVIDENCE",
        "UNKNOWN",
    )

    action = nodes["action-run-authenticated-validation"]
    assert action.status == "proposed"
    assert action.attributes["account_authority_required"] is True
    assert action.attributes["external_submission"] is False


def test_pack_remembers_only_four_confirmed_public_findings() -> None:
    pack = load_memory_pack_json(PACK_PATH.read_text(encoding="utf-8"))
    nodes = {node.id: node for node in pack.graph.nodes}
    situation = nodes["situation-evidence-separated-product-audit"]

    assert tuple(situation.attributes["confirmed_findings"]) == (
        "mobile-chart-user-agent-404",
        "mobile-hero-late-discovery",
        "terminal-hidden-mobile-asset",
        "terminal-missing-onboarding-asset",
    )


def test_pack_rejects_growth_pressure_and_authority() -> None:
    pack = load_memory_pack_json(PACK_PATH.read_text(encoding="utf-8"))
    nodes = {node.id: node for node in pack.graph.nodes}
    lesson = nodes["lesson-product-memory-without-overclaim"]

    assert pack.manifest.contains_private_data is False
    assert pack.manifest.execution_authority is False
    assert pack.manifest.merge_authority is False
    assert lesson.attributes["clickfunnels_role"] == "pattern_reference_only"
    assert lesson.attributes["false_urgency"] is False
    assert lesson.attributes["pressure_to_trade"] is False
    assert lesson.attributes["human_review_required"] is True


def test_selected_path_requires_validation_before_reuse() -> None:
    pack = load_memory_pack_json(PACK_PATH.read_text(encoding="utf-8"))

    assert pack.graph.selected_path == (
        "situation-evidence-separated-product-audit",
        "constraint-authenticated-journeys-unproven",
        "action-run-authenticated-validation",
        "lesson-product-memory-without-overclaim",
    )
