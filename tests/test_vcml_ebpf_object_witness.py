from pathlib import Path

import pytest

from cml.integrations.vcml_ebpf_completed_read_witness import (
    completed_read_object_witness_from_vcml_jsonl,
    completed_read_object_witness_from_vcml_records,
)


def test_object_witness_keeps_success_and_eof_bindings_only():
    witness = completed_read_object_witness_from_vcml_records(
        [
            {
                "action": "read_exit",
                "read_id": "read-a",
                "object": {
                    "return_value": 8,
                    "object_id": "linux-inode:1:101",
                },
            },
            {
                "action": "read_exit",
                "read_id": "read-b",
                "object": {
                    "return_value": 0,
                    "object_id": "linux-inode:1:102",
                },
            },
            {
                "action": "read_exit",
                "read_id": "read-c",
                "object": {"return_value": -9},
            },
        ],
        scope_id="session-1",
    )

    assert tuple(
        (binding.read_id, binding.object_id)
        for binding in witness.completed_bindings
    ) == (
        ("read-a", "linux-inode:1:101"),
        ("read-b", "linux-inode:1:102"),
    )
    assert witness.as_identity_witness().completed_read_ids == ("read-a", "read-b")


def test_successful_exit_without_kernel_object_id_fails_closed():
    with pytest.raises(ValueError, match="non-empty object_id"):
        completed_read_object_witness_from_vcml_records(
            [
                {
                    "action": "read_exit",
                    "read_id": "read-a",
                    "object": {"return_value": 4},
                }
            ],
            scope_id="session-1",
        )


def test_failed_exit_may_have_unresolved_object():
    witness = completed_read_object_witness_from_vcml_records(
        [
            {
                "action": "read_exit",
                "read_id": "bad-fd",
                "object": {"return_value": -9},
            }
        ],
        scope_id="session-1",
    )

    assert witness.completed_bindings == ()


def test_duplicate_exit_identity_fails_closed_for_object_projection():
    with pytest.raises(ValueError, match="duplicate read_exit read_id"):
        completed_read_object_witness_from_vcml_records(
            [
                {
                    "action": "read_exit",
                    "read_id": "read-a",
                    "object": {
                        "return_value": 1,
                        "object_id": "linux-inode:1:101",
                    },
                },
                {
                    "action": "read_exit",
                    "read_id": "read-a",
                    "object": {
                        "return_value": 1,
                        "object_id": "linux-inode:1:102",
                    },
                },
            ],
            scope_id="session-1",
        )


def test_unavailable_object_witness_never_carries_bindings():
    witness = completed_read_object_witness_from_vcml_jsonl(
        [],
        scope_id="session-1",
        available=False,
    )

    assert witness.available is False
    assert witness.completed_bindings == ()
    assert witness.as_identity_witness().available is False


def test_jsonl_object_projection_is_fail_closed():
    witness = completed_read_object_witness_from_vcml_jsonl(
        [
            '{"action":"read_exit","read_id":"read-a","object":{"return_value":1,"object_id":"linux-inode:8:99"}}\n'
        ],
        scope_id="session-1",
    )

    assert witness.completed_bindings[0].object_id == "linux-inode:8:99"


def test_file_monitor_captures_fd_object_at_read_entry_and_carries_it_to_exit():
    source = (
        Path(__file__).resolve().parents[1] / "vcml/linux-ebpf/file_monitor.py"
    ).read_text(encoding="utf-8")

    assert "#include <linux/fdtable.h>" in source
    assert "resolve_fd_object(args->fd, &data.dev, &data.inode)" in source
    assert "start.dev = data.dev;" in source
    assert "start.inode = data.inode;" in source
    assert "start.object_resolved = data.object_resolved;" in source
    assert "data.dev = start->dev;" in source
    assert "data.inode = start->inode;" in source
    assert "data.object_resolved = start->object_resolved;" in source
    assert source.count("_append_kernel_object_identity(obj, event)") == 2
    assert '"kernel_fd_at_sys_enter_read"' in source
