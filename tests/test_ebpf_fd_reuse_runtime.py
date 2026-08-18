import pytest

from cml.integrations.ebpf_fd_reuse_runtime import (
    FAIL,
    PASS,
    evaluate_fd_reuse_runtime_proof,
)


def _event(fd: int, device: int, inode: int, started_ns: int, ret: int = 1):
    return {
        "fd": fd,
        "device": device,
        "inode": inode,
        "return_value": ret,
        "started_ns": started_ns,
        "object_resolved": 1,
    }


def test_runtime_proof_passes_only_for_same_fd_and_distinct_expected_objects():
    result = evaluate_fd_reuse_runtime_proof(
        expected_a={"device": 10, "inode": 101},
        expected_b={"device": 10, "inode": 202},
        workload={"fd_a": 3, "fd_b": 3},
        events=[
            _event(3, 10, 101, 100),
            _event(3, 10, 202, 200),
        ],
    )

    assert result["status"] == PASS
    assert all(result["assertions"].values())


def test_same_fd_with_same_object_fails_reuse_identity_proof():
    result = evaluate_fd_reuse_runtime_proof(
        expected_a={"device": 10, "inode": 101},
        expected_b={"device": 10, "inode": 101},
        workload={"fd_a": 3, "fd_b": 3},
        events=[
            _event(3, 10, 101, 100),
            _event(3, 10, 101, 200),
        ],
    )

    assert result["status"] == FAIL
    assert result["assertions"]["expected_objects_are_distinct"] is False
    assert result["assertions"]["captured_objects_are_distinct"] is False


def test_different_numeric_fds_do_not_prove_fd_reuse():
    result = evaluate_fd_reuse_runtime_proof(
        expected_a={"device": 10, "inode": 101},
        expected_b={"device": 10, "inode": 202},
        workload={"fd_a": 3, "fd_b": 4},
        events=[
            _event(3, 10, 101, 100),
            _event(4, 10, 202, 200),
        ],
    )

    assert result["status"] == FAIL
    assert result["assertions"]["workload_reused_same_fd"] is False
    assert result["assertions"]["captured_same_fd_for_both_reads"] is False


def test_stale_object_binding_on_second_read_fails():
    result = evaluate_fd_reuse_runtime_proof(
        expected_a={"device": 10, "inode": 101},
        expected_b={"device": 10, "inode": 202},
        workload={"fd_a": 3, "fd_b": 3},
        events=[
            _event(3, 10, 101, 100),
            _event(3, 10, 101, 200),
        ],
    )

    assert result["status"] == FAIL
    assert result["assertions"]["second_read_matches_file_b"] is False
    assert result["assertions"]["captured_objects_are_distinct"] is False


def test_unresolved_kernel_object_fails():
    event_b = _event(3, 10, 202, 200)
    event_b["object_resolved"] = 0

    result = evaluate_fd_reuse_runtime_proof(
        expected_a={"device": 10, "inode": 101},
        expected_b={"device": 10, "inode": 202},
        workload={"fd_a": 3, "fd_b": 3},
        events=[_event(3, 10, 101, 100), event_b],
    )

    assert result["status"] == FAIL
    assert result["assertions"]["both_kernel_objects_resolved"] is False


def test_failed_read_does_not_count_as_runtime_success():
    result = evaluate_fd_reuse_runtime_proof(
        expected_a={"device": 10, "inode": 101},
        expected_b={"device": 10, "inode": 202},
        workload={"fd_a": 3, "fd_b": 3},
        events=[
            _event(3, 10, 101, 100),
            _event(3, 10, 202, 200, ret=-5),
        ],
    )

    assert result["status"] == FAIL
    assert result["assertions"]["both_reads_completed_successfully"] is False


def test_extra_target_read_fails_instead_of_selecting_convenient_pair():
    result = evaluate_fd_reuse_runtime_proof(
        expected_a={"device": 10, "inode": 101},
        expected_b={"device": 10, "inode": 202},
        workload={"fd_a": 3, "fd_b": 3},
        events=[
            _event(3, 10, 101, 50),
            _event(3, 10, 101, 100),
            _event(3, 10, 202, 200),
        ],
    )

    assert result["status"] == FAIL
    assert result["assertions"]["captured_exactly_two_reads"] is False


def test_invalid_event_shape_fails_closed():
    with pytest.raises(ValueError, match="event 1.inode"):
        evaluate_fd_reuse_runtime_proof(
            expected_a={"device": 10, "inode": 101},
            expected_b={"device": 10, "inode": 202},
            workload={"fd_a": 3, "fd_b": 3},
            events=[
                {
                    "fd": 3,
                    "device": 10,
                    "inode": "101",
                    "return_value": 1,
                    "started_ns": 100,
                    "object_resolved": 1,
                }
            ],
        )
