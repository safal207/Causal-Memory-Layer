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
    / "chatgpt_public_mobile_web_v1.json"
)


def _pack():
    return load_memory_pack_json(PACK_PATH.read_text(encoding="utf-8"))


def test_chatgpt_mobile_web_pack_is_canonical_and_advisory() -> None:
    pack = _pack()

    result = verify_memory_pack(pack)
    assert result.passed(), result.findings
    assert pack.pack_id == derive_memory_pack_id(
        pack.manifest,
        pack.graph,
        pack.evidence,
        pack.redactions,
    )
    assert pack.pack_id == (
        "17bda596a7530302a35eeed0336907dd96e35c1349f5694e246d1cc0b147e75b"
    )
    assert pack.manifest.contains_private_data is False
    assert pack.manifest.execution_authority is False
    assert pack.manifest.merge_authority is False


def test_memory_preserves_scoped_pass_and_one_diagnostic() -> None:
    pack = _pack()
    nodes = {node.id: node for node in pack.graph.nodes}
    situation = nodes["situation-public-mobile-baseline"]
    lesson = nodes["lesson-preserve-scoped-pass-and-diagnostic"]

    assert situation.attributes["p3_diagnostic"] == "mobile-login-console-error"
    assert len(tuple(situation.attributes["scoped_passes"])) == 7
    assert lesson.attributes["final_verdict"] == "ALLOW_BOUNDED_DIAGNOSTIC"
    assert lesson.attributes["confirmed_diagnostic_count"] == 1
    assert lesson.attributes["rejected_false_positive_count"] == 3
    assert lesson.attributes["human_review_required"] is True


def test_public_scope_blocks_authenticated_native_and_security_claims() -> None:
    pack = _pack()
    nodes = {node.id: node for node in pack.graph.nodes}
    constraint = nodes["constraint-public-scope-only"]
    action = nodes["action-run-authenticated-mobile-audit"]

    assert constraint.status == "verified"
    assert constraint.attributes["authenticated_claims_allowed"] is False
    assert constraint.attributes["native_app_claims_allowed"] is False
    assert constraint.attributes["security_claim_allowed"] is False
    assert action.status == "proposed"
    assert action.attributes["account_authority_required"] is True
    assert action.attributes["external_submission"] is False


def test_selected_path_requires_authenticated_evidence_before_broadening() -> None:
    pack = _pack()

    assert pack.graph.selected_path == (
        "situation-public-mobile-baseline",
        "constraint-public-scope-only",
        "action-run-authenticated-mobile-audit",
        "lesson-preserve-scoped-pass-and-diagnostic",
    )
