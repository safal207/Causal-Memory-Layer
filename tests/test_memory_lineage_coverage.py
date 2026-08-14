from __future__ import annotations

import json
from pathlib import Path

import pytest

from cml.integrations.memory_lineage_coverage import (
    LineageCoverageDependency,
    LineageCoverageRecord,
    lineage_coverage_gaps,
    measure_lineage_verification_coverage,
)

FIXTURE = Path(__file__).parent / "fixtures" / "memory_lineage_coverage_v0.1.json"


def _record(payload: dict[str, object]) -> LineageCoverageRecord:
    dependencies = tuple(
        LineageCoverageDependency(**dependency)
        for dependency in payload.get("dependencies", [])
    )
    return LineageCoverageRecord(
        record_id=payload["record_id"],
        is_derived=payload["is_derived"],
        dependencies=dependencies,
    )


def test_frozen_lineage_verification_coverage_contract() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    contract = payload["benchmark_contract"]
    records = tuple(_record(item) for item in payload["records"])

    result = measure_lineage_verification_coverage(
        records,
        derived_population_enumerable=payload["derived_population_enumerable"],
    )

    assert contract["denominator_includes_missing_lineage"] is True
    assert contract["state_precedes_digest"] is True
    assert contract["digest_mismatch_counts_as_verified"] is True
    assert contract["undefined_is_null_not_zero"] is True

    assert result.eligible_derived_records == contract[
        "expected_eligible_derived_records"
    ]
    assert result.verified_derived_records == contract[
        "expected_verified_derived_records"
    ]
    assert result.uncovered_derived_records == contract[
        "expected_uncovered_derived_records"
    ]
    assert result.coverage == (
        contract["expected_coverage_numerator"]
        / contract["expected_coverage_denominator"]
    )
    assert result.undefined_reason is None

    gaps = {gap.record_id: gap.reasons for gap in result.gaps}
    for item in payload["records"]:
        if not item["is_derived"]:
            assert item["record_id"] not in gaps
            continue
        expected = tuple(item["expected_gaps"])
        assert lineage_coverage_gaps(_record(item)) == expected, item["record_id"]
        assert (item["record_id"] not in gaps) is item["expected_verified"]
        if expected:
            assert gaps[item["record_id"]] == expected


def test_unenumerable_population_is_null_not_zero() -> None:
    result = measure_lineage_verification_coverage(
        (),
        derived_population_enumerable=False,
    )

    assert result.coverage is None
    assert result.undefined_reason == "derived_population_unenumerable"
    assert result.eligible_derived_records == 0
    assert result.verified_derived_records == 0
    assert result.uncovered_derived_records == 0
    assert result.gaps == ()


def test_empty_enumerable_derived_population_is_null_not_zero() -> None:
    result = measure_lineage_verification_coverage(
        (
            LineageCoverageRecord(
                record_id="direct-only",
                is_derived=False,
            ),
        )
    )

    assert result.coverage is None
    assert result.undefined_reason == "no_eligible_derived_records"


def test_erased_state_is_decisive_before_missing_digest() -> None:
    record = LineageCoverageRecord(
        record_id="derived-erased",
        is_derived=True,
        dependencies=(
            LineageCoverageDependency(
                dependency_id="dep-erased",
                state="erased",
                expected_digest="a" * 64,
                observed_digest=None,
            ),
        ),
    )

    assert lineage_coverage_gaps(record) == ()


def test_digest_mismatch_is_verified_even_when_applicability_will_revalidate() -> None:
    record = LineageCoverageRecord(
        record_id="derived-changed",
        is_derived=True,
        dependencies=(
            LineageCoverageDependency(
                dependency_id="dep-changed",
                state="active",
                expected_digest="a" * 64,
                observed_digest="b" * 64,
            ),
        ),
    )

    result = measure_lineage_verification_coverage((record,))

    assert result.coverage == 1.0
    assert result.verified_derived_records == 1
    assert result.gaps == ()


def test_dependency_list_is_snapshotted_not_shared() -> None:
    mutable_dependencies: list[LineageCoverageDependency] = []
    record = LineageCoverageRecord(
        record_id="derived-snapshot",
        is_derived=True,
        dependencies=mutable_dependencies,
    )
    assert isinstance(record.dependencies, tuple)

    mutable_dependencies.append(
        LineageCoverageDependency(dependency_id="dep-late", state="active")
    )

    assert record.dependencies == ()
    assert lineage_coverage_gaps(record) == ("lineage_undeclared",)


def test_dependency_entries_must_be_lineage_coverage_dependency() -> None:
    with pytest.raises(TypeError, match="LineageCoverageDependency"):
        LineageCoverageRecord(
            record_id="derived-invalid-dep",
            is_derived=True,
            dependencies=("not-a-dependency",),
        )


def test_measurement_rejects_duplicate_record_id_before_filtering() -> None:
    covered = LineageCoverageRecord(
        record_id="derived-duplicate",
        is_derived=True,
        dependencies=(
            LineageCoverageDependency(
                dependency_id="dep-active",
                state="active",
                expected_digest="a" * 64,
                observed_digest="a" * 64,
            ),
        ),
    )
    uncovered = LineageCoverageRecord(
        record_id="derived-duplicate",
        is_derived=True,
    )

    with pytest.raises(ValueError, match="duplicate record_id in population"):
        measure_lineage_verification_coverage((covered, uncovered))


def test_duplicate_record_id_is_rejected_even_when_population_unenumerable() -> None:
    record = LineageCoverageRecord(record_id="derived-duplicate", is_derived=True)

    with pytest.raises(ValueError, match="duplicate record_id in population"):
        measure_lineage_verification_coverage(
            (record, record),
            derived_population_enumerable=False,
        )
