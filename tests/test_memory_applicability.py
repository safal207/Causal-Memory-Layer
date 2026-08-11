from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from cml.integrations.memory_applicability import (
    ApplicabilityStatus,
    EnvironmentBinding,
    SourceObservation,
    evaluate_memory_applicability,
)

FIXTURE = Path(__file__).parent / "fixtures" / "memory_applicability_v0.1.json"


def _now(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def test_vendor_neutral_applicability_fixtures() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    now = _now(payload["now"])

    observed_statuses: set[str] = set()
    for case in payload["cases"]:
        result = evaluate_memory_applicability(
            source=SourceObservation(**case["source"]),
            stored_environment=EnvironmentBinding(**case["stored_environment"]),
            current_environment=EnvironmentBinding(**case["current_environment"]),
            now=now,
            caller_metadata=case["caller_metadata"],
        )
        observed_statuses.add(result.status.value)
        assert result.status.value == case["expected_status"], case["id"]
        assert result.may_influence_action is (
            result.status is ApplicabilityStatus.MATCH
        )

    assert observed_statuses == {
        "MATCH",
        "DRIFT",
        "ORPHAN",
        "UNRESOLVABLE",
        "REJECT",
        "REVALIDATE",
    }


def test_reserved_metadata_rejects_before_source_checks() -> None:
    result = evaluate_memory_applicability(
        source=SourceObservation(
            locator=None,
            refetchable=False,
            exists=None,
        ),
        stored_environment=EnvironmentBinding(),
        current_environment=EnvironmentBinding(),
        now=datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc),
        caller_metadata={"_cml_environment_verified": True},
    )

    assert result.status is ApplicabilityStatus.REJECT
    assert result.reasons == ("reserved_metadata:_cml_environment_verified",)


def test_missing_current_bound_dimension_requires_revalidation() -> None:
    digest = "a" * 64
    result = evaluate_memory_applicability(
        source=SourceObservation(
            locator="https://example.test/source",
            refetchable=True,
            exists=True,
            expected_digest=digest,
            observed_digest=digest,
        ),
        stored_environment=EnvironmentBinding(tenant="tenant-a"),
        current_environment=EnvironmentBinding(),
        now=datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc),
    )

    assert result.status is ApplicabilityStatus.REVALIDATE
    assert result.reasons == ("environment_mismatch:tenant",)


def test_reasons_are_stably_sorted() -> None:
    digest = "a" * 64
    result = evaluate_memory_applicability(
        source=SourceObservation(
            locator="https://example.test/source",
            refetchable=True,
            exists=True,
            expected_digest=digest,
            observed_digest=digest,
        ),
        stored_environment=EnvironmentBinding(branch="main", workspace="prod"),
        current_environment=EnvironmentBinding(branch="dev", workspace="staging"),
        now=datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc),
    )

    assert result.reasons == (
        "environment_mismatch:branch",
        "environment_mismatch:workspace",
    )


@pytest.mark.parametrize(
    "bad_metadata",
    [
        {"environment_verified": True},
        {"provenance_verified": True},
        {"source_verified": True},
        {"applicability_verdict": "MATCH"},
        {"warrant": "earned"},
        {"_cml_any_internal_state": True},
    ],
)
def test_caller_cannot_forge_internal_trust_state(bad_metadata: dict[str, object]) -> None:
    result = evaluate_memory_applicability(
        source=SourceObservation(locator=None, refetchable=False, exists=None),
        stored_environment=EnvironmentBinding(),
        current_environment=EnvironmentBinding(),
        now=datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc),
        caller_metadata=bad_metadata,
    )

    assert result.status is ApplicabilityStatus.REJECT
