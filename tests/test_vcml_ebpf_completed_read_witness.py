import pytest

from cml.integrations.vcml_ebpf_completed_read_witness import (
    DEFAULT_COMPLETION_SOURCE_ID,
    completed_read_witness_from_vcml_jsonl,
    completed_read_witness_from_vcml_records,
)


def test_completion_witness_distinguishes_success_eof_and_failure():
    witness = completed_read_witness_from_vcml_records(
        [
            {"action": "read", "object": {"fd": 3, "count": 64}},
            {"action": "read_exit", "object": {"return_value": 64}},
            {"action": "read", "object": {"fd": 3, "count": 64}},
            {"action": "read_exit", "object": {"return_value": 0}},
            {"action": "read", "object": {"fd": 3, "count": 64}},
            {"action": "read_exit", "object": {"return_value": -5}},
        ],
        scope_id="session-1",
    )

    assert witness.source_id == DEFAULT_COMPLETION_SOURCE_ID
    assert witness.scope_id == "session-1"
    assert witness.attempts_seen == 3
    assert witness.exit_events_seen == 3
    assert witness.completed_reads == 2
    assert witness.zero_byte_reads == 1
    assert witness.failed_reads == 1
    assert witness.bytes_returned == 64
    assert witness.available is True


def test_return_value_not_text_status_controls_classification():
    witness = completed_read_witness_from_vcml_records(
        [
            {
                "action": "read_exit",
                "object": {"return_value": -13, "status": "success"},
            }
        ],
        scope_id="session-1",
    )

    assert witness.completed_reads == 0
    assert witness.failed_reads == 1
    assert witness.bytes_returned == 0


def test_zero_return_is_successful_completion_not_failure():
    witness = completed_read_witness_from_vcml_records(
        [{"action": "read_exit", "object": {"return_value": 0}}],
        scope_id="session-1",
    )

    assert witness.completed_reads == 1
    assert witness.zero_byte_reads == 1
    assert witness.failed_reads == 0
    assert witness.bytes_returned == 0


def test_positive_return_values_accumulate_bytes_returned():
    witness = completed_read_witness_from_vcml_records(
        [
            {"action": "read_exit", "object": {"return_value": 10}},
            {"action": "read_exit", "object": {"return_value": 7}},
        ],
        scope_id="session-1",
    )

    assert witness.completed_reads == 2
    assert witness.bytes_returned == 17


def test_completion_projection_uses_only_successful_completions():
    witness = completed_read_witness_from_vcml_records(
        [
            {"action": "read", "object": {"fd": 3, "count": 8}},
            {"action": "read_exit", "object": {"return_value": 8}},
            {"action": "read", "object": {"fd": 3, "count": 8}},
            {"action": "read_exit", "object": {"return_value": -5}},
        ],
        scope_id="session-1",
    )

    projected = witness.as_completed_external_witness()

    assert projected.scope_id == "session-1"
    assert projected.source_id == DEFAULT_COMPLETION_SOURCE_ID
    assert projected.reads_count == 1
    assert projected.available is True


def test_missing_return_value_fails_closed():
    with pytest.raises(ValueError, match="integer return_value"):
        completed_read_witness_from_vcml_records(
            [{"action": "read_exit", "object": {"status": "success"}}],
            scope_id="session-1",
        )


def test_non_mapping_read_exit_object_fails_closed():
    with pytest.raises(ValueError, match="object mapping"):
        completed_read_witness_from_vcml_records(
            [{"action": "read_exit", "object": "not-an-object"}],
            scope_id="session-1",
        )


def test_jsonl_completion_parser_fails_closed_on_malformed_json():
    with pytest.raises(ValueError, match="invalid vCML JSONL at line 2"):
        completed_read_witness_from_vcml_jsonl(
            [
                '{"action":"read_exit","object":{"return_value":4}}\n',
                "not-json\n",
            ],
            scope_id="session-1",
        )


def test_unavailable_completion_monitor_is_explicit():
    witness = completed_read_witness_from_vcml_jsonl(
        [],
        scope_id="session-1",
        available=False,
    )

    projected = witness.as_completed_external_witness()

    assert witness.available is False
    assert witness.attempts_seen == 0
    assert witness.exit_events_seen == 0
    assert projected.available is False
    assert projected.reads_count == 0


def test_aggregate_summary_does_not_require_visible_attempt_for_exit():
    witness = completed_read_witness_from_vcml_records(
        [{"action": "read_exit", "object": {"return_value": 4}}],
        scope_id="session-1",
    )

    # Perf-buffer loss can make entry/exit counts diverge. Without a stable
    # cross-boundary read id, the adapter records what it saw instead of
    # inventing an exact pairing claim.
    assert witness.attempts_seen == 0
    assert witness.exit_events_seen == 1
    assert witness.completed_reads == 1
    assert witness.bytes_returned == 4


def test_non_mapping_record_fails_closed():
    with pytest.raises(TypeError, match="record 1 must be a mapping"):
        completed_read_witness_from_vcml_records(  # type: ignore[arg-type]
            ["read_exit"],
            scope_id="session-1",
        )
