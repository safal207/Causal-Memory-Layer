"""Deterministic source-side reconciliation for memory provenance.

A populated source field is not equivalent to a re-fetchable or enumerable
origin. This module keeps those measurements separate and performs the one
comparison that can detect missed deletions: complete source enumeration
against the index.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class IndexedSourceRecord:
    """Measured provenance facts for one indexed memory record."""

    memory_id: str
    source_label: str | None = None
    source_namespace: str | None = None
    source_id: str | None = None
    locator: str | None = None
    refetchable: bool = False
    exists: bool | None = None
    expected_digest: str | None = None
    observed_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.memory_id, str) or not self.memory_id.strip():
            raise ValueError("memory_id must be a non-empty string")
        for name in ("source_label", "source_namespace", "source_id", "locator"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be non-empty when provided")
        if not isinstance(self.refetchable, bool):
            raise TypeError("refetchable must be boolean")
        if self.exists is not None and not isinstance(self.exists, bool):
            raise TypeError("exists must be boolean or None")
        if self.refetchable and self.locator is None:
            raise ValueError("refetchable records must carry a locator")


@dataclass(frozen=True)
class SourceInventory:
    """A trusted source-side enumeration for one authoritative namespace."""

    namespace: str
    source_ids: tuple[str, ...]
    complete: bool

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, str) or not self.namespace.strip():
            raise ValueError("namespace must be a non-empty string")
        if not isinstance(self.complete, bool):
            raise TypeError("complete must be boolean")
        if any(not isinstance(value, str) or not value.strip() for value in self.source_ids):
            raise ValueError("source_ids must contain only non-empty strings")
        if len(set(self.source_ids)) != len(self.source_ids):
            raise ValueError("source_ids must be unique within one inventory")


@dataclass(frozen=True)
class ProvenanceCoverage:
    total_records: int
    source_field_count: int
    locator_count: int
    refetchable_count: int
    refetch_verified_count: int
    source_enumerable_count: int

    @staticmethod
    def _ratio(count: int, total: int) -> float:
        return 0.0 if total == 0 else count / total

    @property
    def source_field_coverage(self) -> float:
        return self._ratio(self.source_field_count, self.total_records)

    @property
    def locator_coverage(self) -> float:
        return self._ratio(self.locator_count, self.total_records)

    @property
    def refetchable_coverage(self) -> float:
        return self._ratio(self.refetchable_count, self.total_records)

    @property
    def refetch_verification_coverage(self) -> float:
        return self._ratio(self.refetch_verified_count, self.total_records)

    @property
    def source_enumeration_coverage(self) -> float:
        return self._ratio(self.source_enumerable_count, self.total_records)


@dataclass(frozen=True)
class SourceReconciliationResult:
    coverage: ProvenanceCoverage
    orphaned_index_sources: tuple[str, ...]
    unindexed_source_ids: tuple[str, ...]
    incomplete_namespaces: tuple[str, ...]

    @property
    def exact_source_diff_available(self) -> bool:
        return not self.incomplete_namespaces

    @property
    def clean(self) -> bool:
        return (
            self.exact_source_diff_available
            and not self.orphaned_index_sources
            and not self.unindexed_source_ids
        )


def _refetch_verified(record: IndexedSourceRecord) -> bool:
    if not record.refetchable or record.exists is None:
        return False
    if record.exists is False:
        return True
    return record.expected_digest is not None and record.observed_digest is not None


def reconcile_memory_sources(
    records: Iterable[IndexedSourceRecord],
    inventories: Iterable[SourceInventory],
) -> SourceReconciliationResult:
    """Measure provenance coverage and source-side/index-side drift.

    Only a complete source inventory is allowed to decide that an indexed source
    was deleted or that a current source has no indexed representation. Partial
    inventories are reported explicitly rather than converted into clean zeros.
    """

    records = tuple(records)
    inventories = tuple(inventories)
    by_namespace = {inventory.namespace: inventory for inventory in inventories}
    if len(by_namespace) != len(inventories):
        raise ValueError("only one inventory per namespace is allowed")

    complete_namespaces = {
        namespace for namespace, inventory in by_namespace.items() if inventory.complete
    }
    incomplete_namespaces = tuple(
        sorted(
            namespace
            for namespace, inventory in by_namespace.items()
            if not inventory.complete
        )
    )

    coverage = ProvenanceCoverage(
        total_records=len(records),
        source_field_count=sum(record.source_label is not None for record in records),
        locator_count=sum(record.locator is not None for record in records),
        refetchable_count=sum(record.refetchable for record in records),
        refetch_verified_count=sum(_refetch_verified(record) for record in records),
        source_enumerable_count=sum(
            record.source_namespace in complete_namespaces and record.source_id is not None
            for record in records
        ),
    )

    indexed_by_namespace: dict[str, set[str]] = {}
    for record in records:
        if record.source_namespace is None or record.source_id is None:
            continue
        indexed_by_namespace.setdefault(record.source_namespace, set()).add(record.source_id)

    orphaned: list[str] = []
    unindexed: list[str] = []
    for namespace in sorted(complete_namespaces):
        inventory_ids = set(by_namespace[namespace].source_ids)
        indexed_ids = indexed_by_namespace.get(namespace, set())
        orphaned.extend(
            f"{namespace}:{source_id}"
            for source_id in sorted(indexed_ids - inventory_ids)
        )
        unindexed.extend(
            f"{namespace}:{source_id}"
            for source_id in sorted(inventory_ids - indexed_ids)
        )

    return SourceReconciliationResult(
        coverage=coverage,
        orphaned_index_sources=tuple(orphaned),
        unindexed_source_ids=tuple(unindexed),
        incomplete_namespaces=incomplete_namespaces,
    )
