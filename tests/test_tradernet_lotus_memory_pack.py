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
    / "tradernet_mobile_public_qa_v1.json"
)


def test_tradernet_lotus_memory_pack_is_canonical_and_advisory() -> None:
    pack = load_memory_pack_json(PACK_PATH.read_text(encoding="utf-8"))

    assert verify_memory_pack(pack).passed()
    assert pack.pack_id == derive_memory_pack_id(
        pack.manifest,
        pack.graph,
        pack.evidence,
        pack.redactions,
    )
    assert pack.pack_id == (
        "f5bac00f1be20c9ca5717236b0e5d0b2c433bc8ff780101736fa267e1c097609"
    )
    assert pack.manifest.contains_private_data is False
    assert pack.manifest.execution_authority is False
    assert pack.manifest.merge_authority is False
    assert pack.graph.selected_path == (
        "situation-repeated-mobile-defects",
        "cause-mobile-device-branch",
        "action-test-mobile-branch",
        "check-preserve-unknowns",
        "lesson-bounded-mobile-cluster",
    )

    nodes = {node.id: node for node in pack.graph.nodes}
    shared_cause = nodes["cause-mobile-device-branch"]
    assert shared_cause.status == "proposed"
    assert shared_cause.confidence == 75
    assert shared_cause.attributes["must_not_be_reported_as_fact"] is True
