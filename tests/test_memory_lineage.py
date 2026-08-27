from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from cml.integrations.memory_applicability import (
    ApplicabilityStatus,
    EnvironmentBinding,
    LineageDependency,
    SourceObservation,
    evaluate_memory_applicability,
)

FIXTURE = Path(__file__).parent / "fixtures" / "memory_lineage_v0.1.json"


def _now(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


def _lineage(payload: list[dict[str, object]]) -> tuple[LineageDependency, ...]:
    return tuple(LineageDependency(**item) for item in payload)


def test_frozen_lineage_fixture_with_negative_controls_and_exclusion_accounting() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    contract = payload["benchmark_contract"]
    included = [case for case in payload["cases"] if not case.get("exclude", False)]
    excluded = [case for case in payload["cases"] if case.get("exclude", False)]

    assert contract["negative_control_required"] is True
    assert contract["exclusion_accounting_required"] is True
    assert len(included) == contract["expected_included"]
    assert len(excluded) == contract["expected_excluded"]
    assert all(case.get("exclusion_reason") for case in excluded)

    source = SourceObservation(**payload["source"])
    stored_environment = EnvironmentBinding(**payload["stored_environment"])
    current_environment = EnvironmentBinding(**payload["current_environment"])
    now = _now(payload["now"])

    target_statuses: set[str] = set()
    control_statuses: set[str] = set()

    for case in included:
        assert "negative_control" in case, case["id"]

        result = evaluate_memory_applicability(
            source=source,
            stored_environment=stored_environment,
            current_environment=current_environment,
            now=now,
            lineage=_lineage(case["lineage"]),
        )
        target_statuses.add(result.status.value)
        assert result.status.value == case["expected_status"], case["id"]
        assert result.reasons == tuple(case["expected_reasons"]), case["id"]
        assert result.may_influence_action is False

        control = case["negative_control"]
        control_result = evaluate_memory_applicability(
            source=source,
            stored_environment=stored_environment,
            current_environment=current_environment,
            now=now,
            lineage=_lineage(control["lineage"]),
        )
        control_statuses.add(control_result.status.value)
        assert control_result.status.value == control["expected_status"], case["id"]
        assert control_result.reasons == ()
        assert control_result.may_influence_action is True

    assert target_statuses == {"REVALIDATE"}
    assert control_statuses == {"MATCH"}


def test_source_integrity_precedes_lineage_invalidation() -> None:
    result = evaluate_memory_applicability(
        source=SourceObservation(
            locator="https://example.test/derived-summary",
            refetchable=True,
            exists=True,
            expected_digest="a" * 64,
            observed_digest="b" * 64,
        ),
        stored_environment=EnvironmentBinding(),
        current_environment=EnvironmentBinding(),
        now=datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc),
        lineage=(
            LineageDependency(
                dependency_id="dep-a",
                state="erased",
                expected_digest="a" * 64,
                observed_digest=None,
            ),
        ),
    )

    assert result.status is ApplicabilityStatus.DRIFT
    assert result.reasons == ("source_digest_mismatch",)


def test_lineage_and_environment_revalidation_reasons_are_combined_and_sorted() -> None:
    result = evaluate_memory_applicability(
        source=SourceObservation(
            locator="https://example.test/derived-summary",
            refetchable=True,
            exists=True,
            expected_digest="a" * 64,
            observed_digest="a" * 64,
        ),
        stored_environment=EnvironmentBinding(tenant="tenant-a"),
        current_environment=EnvironmentBinding(tenant="tenant-b"),
        now=datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc),
        lineage=(
            LineageDependency(
                dependency_id="dep-b",
                state="retired",
                expected_digest="b" * 64,
                observed_digest="b" * 64,
            ),
        ),
    )

    assert result.status is ApplicabilityStatus.REVALIDATE
    assert result.reasons == (
        "environment_mismatch:tenant",
        "lineage_invalidated:dep-b:retired",
    )
