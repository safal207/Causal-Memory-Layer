import json
from pathlib import Path

import pytest

from cml.integrations.crewai_event_record import (
    snapshots_from_crewai_event_record,
    validate_crewai_event_record,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "crewai_event_record_v1.json"
FIXTURES = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", FIXTURES["cases"], ids=lambda case: case["name"])
def test_crewai_event_record_fixtures(case: dict) -> None:
    result = validate_crewai_event_record(case["events"])
    assert sorted({finding.code for finding in result.findings}) == sorted(
        case["expected_codes"]
    )
    assert result.passed() is (not case["expected_codes"])


def test_serialized_event_record_nodes_are_supported() -> None:
    events = FIXTURES["cases"][0]["events"]
    record = {
        "nodes": {
            event["event_id"]: {"event": event, "edges": {}}
            for event in events
        }
    }

    snapshots = snapshots_from_crewai_event_record(record)
    result = validate_crewai_event_record(record)

    assert len(snapshots) == len(events)
    assert result.passed()


def test_findings_are_deterministically_ordered() -> None:
    events = [
        {
            "event_id": "z-event",
            "type": "tool_usage_finished",
            "started_event_id": "missing-z",
            "emission_sequence": 2,
        },
        {
            "event_id": "a-event",
            "type": "task_started",
            "parent_event_id": "missing-a",
            "emission_sequence": 1,
        },
    ]

    first = validate_crewai_event_record(events)
    second = validate_crewai_event_record(reversed(events))

    assert first == second


def test_duplicate_sequences_are_input_order_independent() -> None:
    events = [
        {"event_id": "z-event", "type": "task_started", "emission_sequence": 1},
        {"event_id": "a-event", "type": "task_started", "emission_sequence": 1},
    ]

    first = validate_crewai_event_record(events)
    second = validate_crewai_event_record(reversed(events))

    assert first == second
    duplicate = next(
        finding
        for finding in first.findings
        if finding.field == "emission_sequence"
        and finding.referenced_event_id is not None
    )
    assert duplicate.event_id == "z-event"
    assert duplicate.referenced_event_id == "a-event"


def test_duplicate_ids_use_a_stable_canonical_snapshot_without_hiding_local_findings() -> None:
    events = [
        {
            "event_id": "duplicate",
            "type": "tool_usage_started",
            "parent_event_id": "missing-parent",
            "emission_sequence": 2,
        },
        {
            "event_id": "duplicate",
            "type": "task_started",
            "emission_sequence": 1,
        },
    ]

    first = validate_crewai_event_record(events)
    second = validate_crewai_event_record(reversed(events))

    assert first == second
    assert {
        finding.code for finding in first.findings
    } >= {
        "CML-CREWAI-DUPLICATE-EVENT-ID",
        "CML-CREWAI-ORPHANED-ROOT",
    }


def test_long_acyclic_chain_does_not_recurse() -> None:
    event_count = 1_200
    events = []
    previous_event_id = None
    for index in range(event_count):
        event_id = f"event-{event_count - index:04d}"
        events.append(
            {
                "event_id": event_id,
                "type": "task_started",
                "previous_event_id": previous_event_id,
                "emission_sequence": index + 1,
            }
        )
        previous_event_id = event_id

    result = validate_crewai_event_record(events)

    assert result.passed()
