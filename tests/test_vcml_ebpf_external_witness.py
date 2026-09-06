import pytest

from cml.admissibility_preconditions import check_admissibility_preconditions
from cml.integrations.vcml_ebpf_external_witness import (
    DEFAULT_SOURCE_ID,
    external_witness_from_vcml_jsonl,
    external_witness_from_vcml_records,
)


def test_vcml_records_count_only_read_boundary_events():
    witness = external_witness_from_vcml_records(
        [
            {"action": "open"},
            {"action": "read", "object": {"fd": 3, "count": 32}},
            {"action": "connect"},
            {"action": "read", "object": {"fd": 3, "count": 64}},
        ],
        scope_id="session-1",
    )

    assert witness.source_id == DEFAULT_SOURCE_ID
    assert witness.scope_id == "session-1"
    assert witness.reads_count == 2
    assert witness.available is True


def test_vcml_jsonl_bridge_feeds_dead_collector_precondition():
    witness = external_witness_from_vcml_jsonl(
        [
            '{"action":"open"}\n',
            '{"action":"read","object":{"fd":3,"count":128}}\n',
        ],
        scope_id="session-1",
    )

    result = check_admissibility_preconditions(
        witness=witness,
        ledger_scope_id="session-1",
        ledger_observations=0,
    )

    assert result.applicable is True
    assert result.holds is False
    assert result.reasons == ("observation_channel_missing",)


def test_vcml_jsonl_rejects_malformed_input_instead_of_under_counting():
    with pytest.raises(ValueError, match="invalid vCML JSONL at line 2"):
        external_witness_from_vcml_jsonl(
            ['{"action":"read"}\n', "not-json\n"],
            scope_id="session-1",
        )


def test_vcml_jsonl_rejects_non_object_records():
    with pytest.raises(ValueError, match="must be an object"):
        external_witness_from_vcml_jsonl(
            ['["read"]\n'],
            scope_id="session-1",
        )


def test_unavailable_monitor_is_not_misreported_as_zero_reads():
    witness = external_witness_from_vcml_jsonl(
        [],
        scope_id="session-1",
        available=False,
    )

    result = check_admissibility_preconditions(
        witness=witness,
        ledger_scope_id="session-1",
        ledger_observations=0,
    )

    assert witness.available is False
    assert result.applicable is False
    assert result.holds is False
    assert result.reasons == ("external_witness_unavailable",)


def test_sys_enter_read_semantics_include_attempt_even_without_completion_claim():
    witness = external_witness_from_vcml_records(
        [{"action": "read", "object": {"fd": 3, "count": 0}}],
        scope_id="session-1",
    )

    # v0.5 observes sys_enter_read. This is deliberately a boundary-event count,
    # not proof that bytes were successfully returned to the caller.
    assert witness.reads_count == 1


def test_non_mapping_record_fails_closed():
    with pytest.raises(TypeError, match="record 1 must be a mapping"):
        external_witness_from_vcml_records(  # type: ignore[arg-type]
            ["read"],
            scope_id="session-1",
        )
