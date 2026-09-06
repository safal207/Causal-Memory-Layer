from __future__ import annotations

import json
from pathlib import Path

import pytest

from cml.integrations.memory_source_reconciliation import (
    IndexedSourceRecord,
    SourceInventory,
    reconcile_memory_sources,
)

FIXTURE = Path(__file__).parent / "fixtures" / "memory_source_reconciliation_v0.1.json"


def test_source_reconciliation_fixtures() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))

    for case in payload["cases"]:
        result = reconcile_memory_sources(
            [IndexedSourceRecord(**item) for item in case["records"]],
            [SourceInventory(**item) for item in case["inventories"]],
        )
        expected = case["expected"]
        assert result.coverage.source_field_coverage == pytest.approx(
            expected["source_field_coverage"]
        ), case["id"]
        assert result.coverage.locator_coverage == pytest.approx(
            expected["locator_coverage"]
        ), case["id"]
        assert result.coverage.refetch_verification_coverage == pytest.approx(
            expected["refetch_verification_coverage"]
        ), case["id"]
        assert result.coverage.source_enumeration_coverage == pytest.approx(
            expected["source_enumeration_coverage"]
        ), case["id"]
        assert result.orphaned_index_sources == tuple(expected["orphans"]), case["id"]
        assert result.unindexed_source_ids == tuple(expected["unindexed"]), case["id"]
        assert result.incomplete_namespaces == tuple(
            expected.get("incomplete_namespaces", [])
        ), case["id"]


def test_complete_source_enumeration_is_required_for_deletion_claims() -> None:
    record = IndexedSourceRecord(
        memory_id="m1",
        source_label="doc",
        source_namespace="web",
        source_id="gone",
        locator="https://example.test/gone",
        refetchable=True,
        exists=None,
    )

    partial = reconcile_memory_sources(
        [record],
        [SourceInventory(namespace="web", source_ids=(), complete=False)],
    )
    complete = reconcile_memory_sources(
        [record],
        [SourceInventory(namespace="web", source_ids=(), complete=True)],
    )

    assert partial.orphaned_index_sources == ()
    assert partial.incomplete_namespaces == ("web",)
    assert complete.orphaned_index_sources == ("web:gone",)


def test_refetchable_requires_locator() -> None:
    with pytest.raises(ValueError, match="refetchable records must carry a locator"):
        IndexedSourceRecord(memory_id="m1", refetchable=True)


def test_duplicate_inventory_namespace_fails_closed() -> None:
    with pytest.raises(ValueError, match="one inventory per namespace"):
        reconcile_memory_sources(
            [],
            [
                SourceInventory(namespace="git", source_ids=(), complete=True),
                SourceInventory(namespace="git", source_ids=(), complete=True),
            ],
        )
