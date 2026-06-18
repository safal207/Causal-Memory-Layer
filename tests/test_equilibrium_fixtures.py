import json
from pathlib import Path
from typing import Any

import pytest

from cml.experimental.equilibrium import (
    CausalEquilibriumSnapshot,
    evaluate_causal_equilibrium,
)


SCHEMA_VERSION = "cml-equilibrium-fixtures-v1"
FINDINGS_ORDER = (
    "code_asc,severity_fail_before_warn,refs_lexicographic_asc,message_asc"
)
SEVERITY_RANK = {"FAIL": 0, "WARN": 1}
LIST_FIELDS = (
    "supporting_refs",
    "counter_refs",
    "recalled_memory_refs",
    "unresolved_refs",
    "consolidation_source_refs",
    "consolidation_preserved_refs",
)
CONTRACT_PATH = (
    Path(__file__).resolve().parents[1]
    / "benchmarks"
    / "equilibrium"
    / "v1"
    / "fixtures.json"
)


def _load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def _snapshot(raw: dict[str, Any], *, reverse_lists: bool = False) -> CausalEquilibriumSnapshot:
    list_values = {
        field_name: tuple(
            reversed(raw[field_name]) if reverse_lists else raw[field_name]
        )
        for field_name in LIST_FIELDS
    }
    return CausalEquilibriumSnapshot(
        action_ref=raw["action_ref"],
        require_counterevidence=raw["require_counterevidence"],
        metadata=dict(raw["metadata"]),
        **list_values,
    )


def _serialize_result(result: Any) -> dict[str, Any]:
    return {
        "state": result.state.value,
        "findings": [
            {
                "code": finding.code,
                "severity": finding.severity.value,
                "message": finding.message,
                "refs": list(finding.refs),
            }
            for finding in result.findings
        ],
    }


def _finding_sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding["code"],
        SEVERITY_RANK[finding["severity"]],
        tuple(finding["refs"]),
        finding["message"],
    )


CONTRACT = _load_contract()
FIXTURES = CONTRACT["fixtures"]


def test_fixture_contract_metadata_is_versioned_and_unique() -> None:
    assert CONTRACT["contract_id"] == "cml-causal-equilibrium-conformance-v1"
    assert CONTRACT["schema_version"] == SCHEMA_VERSION
    assert CONTRACT["findings_order"] == FINDINGS_ORDER
    assert len(FIXTURES) >= 10

    fixture_ids = [fixture["fixture_id"] for fixture in FIXTURES]
    assert len(fixture_ids) == len(set(fixture_ids))

    for fixture in FIXTURES:
        assert fixture["schema_version"] == SCHEMA_VERSION
        assert fixture["findings_order"] == FINDINGS_ORDER
        assert fixture["description"]


@pytest.mark.parametrize(
    "fixture",
    FIXTURES,
    ids=[fixture["fixture_id"] for fixture in FIXTURES],
)
def test_fixture_matches_current_equilibrium_evaluator(
    fixture: dict[str, Any],
) -> None:
    snapshot = _snapshot(fixture["snapshot"])
    result = evaluate_causal_equilibrium(
        snapshot,
        known_refs=fixture["known_refs"],
    )

    assert result.action_ref == fixture["snapshot"]["action_ref"]
    assert _serialize_result(result) == {
        "state": fixture["expected_state"],
        "findings": fixture["expected_findings"],
    }


@pytest.mark.parametrize(
    "fixture",
    FIXTURES,
    ids=[fixture["fixture_id"] for fixture in FIXTURES],
)
def test_fixture_result_is_invariant_to_input_collection_order(
    fixture: dict[str, Any],
) -> None:
    original = evaluate_causal_equilibrium(
        _snapshot(fixture["snapshot"]),
        known_refs=fixture["known_refs"],
    )
    reordered = evaluate_causal_equilibrium(
        _snapshot(fixture["snapshot"], reverse_lists=True),
        known_refs=reversed(fixture["known_refs"]),
    )

    assert _serialize_result(reordered) == _serialize_result(original)


@pytest.mark.parametrize(
    "fixture",
    FIXTURES,
    ids=[fixture["fixture_id"] for fixture in FIXTURES],
)
def test_expected_findings_use_canonical_order(
    fixture: dict[str, Any],
) -> None:
    findings = fixture["expected_findings"]

    for finding in findings:
        assert finding["severity"] in SEVERITY_RANK
        assert finding["refs"] == sorted(finding["refs"])

    assert findings == sorted(findings, key=_finding_sort_key)


def test_contract_covers_all_current_equilibrium_states() -> None:
    states = {fixture["expected_state"] for fixture in FIXTURES}
    assert states == {"BALANCED", "UNSTABLE", "INDETERMINATE"}


def test_contract_contains_structurally_complete_but_indeterminate_case() -> None:
    fixture = next(
        item
        for item in FIXTURES
        if item["fixture_id"] == "eq_v1_002_missing_required_counterevidence"
    )

    assert fixture["snapshot"]["supporting_refs"]
    assert fixture["snapshot"]["require_counterevidence"] is True
    assert fixture["snapshot"]["counter_refs"] == []
    assert fixture["expected_state"] == "INDETERMINATE"
