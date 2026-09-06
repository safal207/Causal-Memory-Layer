from pathlib import Path

import pytest

from cml.integrations.vcml_read_id_coverage import (
    reconcile_successful_read_id_coverage,
    reconcile_successful_read_id_coverage_jsonl,
)


def _exit(read_id: str | None, return_value: int):
    record = {
        "action": "read_exit",
        "object": {"return_value": return_value},
    }
    if read_id is not None:
        record["read_id"] = read_id
    return record


def _ledger(read_id: str):
    return {"read_id": read_id}


def test_successful_completion_coverage_holds_by_identity():
    result = reconcile_successful_read_id_coverage(
        [_exit("r-1", 12), _exit("r-2", 0), _exit("failed", -5)],
        [_ledger("r-1"), _ledger("r-2")],
        scope_id="session-1",
    )

    assert result.applicable is True
    assert result.holds is True
    assert result.external_successful_read_ids == ("r-1", "r-2")
    assert result.missing_read_ids == ()
    assert result.covered_count == 2


def test_duplicate_ledger_id_cannot_hide_a_missing_external_read():
    result = reconcile_successful_read_id_coverage(
        [_exit("r-1", 10), _exit("r-2", 20)],
        [_ledger("r-1"), _ledger("r-1")],
        scope_id="session-1",
    )

    assert result.applicable is True
    assert result.holds is False
    assert result.missing_read_ids == ("r-2",)
    assert result.duplicate_ledger_read_ids == ("r-1",)
    assert result.reasons == ("missing_ledger_observations",)


def test_eof_completion_requires_coverage_but_failed_read_does_not():
    result = reconcile_successful_read_id_coverage(
        [_exit("eof", 0), _exit("failed", -1)],
        [],
        scope_id="session-1",
    )

    assert result.holds is False
    assert result.missing_read_ids == ("eof",)
    assert "failed" not in result.external_successful_read_ids


def test_missing_read_id_on_successful_external_completion_fails_closed():
    with pytest.raises(ValueError, match="must contain a non-empty read_id"):
        reconcile_successful_read_id_coverage(
            [_exit(None, 5)],
            [],
            scope_id="session-1",
        )


def test_duplicate_successful_external_read_id_fails_closed():
    with pytest.raises(ValueError, match="duplicate successful external read_id: r-1"):
        reconcile_successful_read_id_coverage(
            [_exit("r-1", 1), _exit("r-1", 2)],
            [_ledger("r-1")],
            scope_id="session-1",
        )


def test_unavailable_external_witness_is_inapplicable():
    result = reconcile_successful_read_id_coverage(
        [],
        [_ledger("r-1")],
        scope_id="session-1",
        external_available=False,
    )

    assert result.applicable is False
    assert result.holds is False
    assert result.reasons == ("external_witness_unavailable",)


def test_no_successful_external_reads_means_coverage_not_exercised():
    result = reconcile_successful_read_id_coverage(
        [_exit("failed", -5)],
        [],
        scope_id="session-1",
    )

    assert result.applicable is False
    assert result.holds is False
    assert result.reasons == ("coverage_not_exercised",)


def test_unexpected_ledger_id_is_diagnostic_not_a_coverage_failure():
    result = reconcile_successful_read_id_coverage(
        [_exit("r-1", 3)],
        [_ledger("r-1"), _ledger("other")],
        scope_id="session-1",
    )

    assert result.holds is True
    assert result.unexpected_ledger_read_ids == ("other",)


def test_jsonl_reconciliation_fails_closed_on_malformed_ledger_stream():
    with pytest.raises(ValueError, match="invalid ledger JSONL at line 1"):
        reconcile_successful_read_id_coverage_jsonl(
            ['{"action":"read_exit","read_id":"r-1","object":{"return_value":1}}\n'],
            ["not-json\n"],
            scope_id="session-1",
        )


@pytest.mark.parametrize("stream_name", ["external", "ledger"])
def test_jsonl_reconciliation_rejects_duplicate_names_at_any_depth(stream_name):
    external = [
        '{"action":"read_exit","read_id":"r-1",'
        '"object":{"return_value":1}}\n'
    ]
    ledger = ['{"read_id":"r-1"}\n']
    duplicate = (
        '{"action":"read_exit","read_id":"r-1",'
        '"object":{"return_value":1,"return_value":-1}}\n'
        if stream_name == "external"
        else '{"read_id":"r-1","read\\u005fid":"substituted"}\n'
    )
    if stream_name == "external":
        external = [duplicate]
    else:
        ledger = [duplicate]

    with pytest.raises(ValueError, match="duplicate JSON key"):
        reconcile_successful_read_id_coverage_jsonl(
            external,
            ledger,
            scope_id="session-1",
        )


def test_monitor_contract_carries_kernel_boundary_identity_to_entry_and_exit():
    source = Path("vcml/linux-ebpf/file_monitor.py").read_text(encoding="utf-8")

    assert "u64 started_ns = bpf_ktime_get_ns();" in source
    assert "start.started_ns = started_ns;" in source
    assert "data.started_ns = start->started_ns;" in source
    assert source.count('"read_id": read_id') >= 2
    assert "linux-read:{pid}:{tid}:{started_ns}" in source
