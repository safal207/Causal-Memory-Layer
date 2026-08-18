"""Evaluate runtime eBPF fd-reuse evidence without depending on BCC.

The runtime harness captures two successful reads performed by one process:
file A is opened/read/closed, then file B is opened/read. Linux should reuse the
same lowest available numeric fd. The proof passes only when the kernel witness
shows the same fd bound to two distinct expected kernel objects.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


PASS = "PASS"
FAIL = "FAIL"
UNSUPPORTED_ENVIRONMENT = "UNSUPPORTED_ENVIRONMENT"


def _object_id(device: int, inode: int) -> str:
    return f"linux-inode:{device}:{inode}"


def evaluate_fd_reuse_runtime_proof(
    *,
    expected_a: Mapping[str, Any],
    expected_b: Mapping[str, Any],
    workload: Mapping[str, Any],
    events: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Return a deterministic PASS/FAIL verdict for captured runtime evidence."""

    required_expected = ("device", "inode")
    for label, expected in (("a", expected_a), ("b", expected_b)):
        for key in required_expected:
            value = expected.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"expected_{label}.{key} must be a non-negative integer")

    fd_a = workload.get("fd_a")
    fd_b = workload.get("fd_b")
    if not isinstance(fd_a, int) or isinstance(fd_a, bool):
        raise ValueError("workload.fd_a must be an integer")
    if not isinstance(fd_b, int) or isinstance(fd_b, bool):
        raise ValueError("workload.fd_b must be an integer")

    normalized_events: list[dict[str, int]] = []
    for index, raw in enumerate(events, start=1):
        if not isinstance(raw, Mapping):
            raise TypeError(f"event {index} must be a mapping")
        event: dict[str, int] = {}
        for key in ("fd", "device", "inode", "return_value", "started_ns"):
            value = raw.get(key)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"event {index}.{key} must be an integer")
            event[key] = value
        resolved = raw.get("object_resolved")
        if resolved not in (0, 1, False, True):
            raise ValueError(f"event {index}.object_resolved must be boolean-like")
        event["object_resolved"] = int(bool(resolved))
        normalized_events.append(event)

    normalized_events.sort(key=lambda item: item["started_ns"])

    assertions: dict[str, bool] = {
        "workload_reused_same_fd": fd_a == fd_b,
        "captured_exactly_two_reads": len(normalized_events) == 2,
        "both_reads_completed_successfully": (
            len(normalized_events) == 2
            and all(event["return_value"] >= 0 for event in normalized_events)
        ),
        "both_kernel_objects_resolved": (
            len(normalized_events) == 2
            and all(event["object_resolved"] == 1 for event in normalized_events)
        ),
        "captured_same_fd_for_both_reads": (
            len(normalized_events) == 2
            and normalized_events[0]["fd"] == normalized_events[1]["fd"] == fd_a
        ),
        "expected_objects_are_distinct": (
            (expected_a["device"], expected_a["inode"])
            != (expected_b["device"], expected_b["inode"])
        ),
        "first_read_matches_file_a": (
            len(normalized_events) == 2
            and normalized_events[0]["device"] == expected_a["device"]
            and normalized_events[0]["inode"] == expected_a["inode"]
        ),
        "second_read_matches_file_b": (
            len(normalized_events) == 2
            and normalized_events[1]["device"] == expected_b["device"]
            and normalized_events[1]["inode"] == expected_b["inode"]
        ),
        "captured_objects_are_distinct": (
            len(normalized_events) == 2
            and (
                normalized_events[0]["device"],
                normalized_events[0]["inode"],
            )
            != (
                normalized_events[1]["device"],
                normalized_events[1]["inode"],
            )
        ),
    }

    passed = all(assertions.values())
    return {
        "schema_version": "cml-ebpf-fd-reuse-runtime-proof-v1",
        "status": PASS if passed else FAIL,
        "assertions": assertions,
        "expected": {
            "a": {
                "device": expected_a["device"],
                "inode": expected_a["inode"],
                "object_id": _object_id(expected_a["device"], expected_a["inode"]),
            },
            "b": {
                "device": expected_b["device"],
                "inode": expected_b["inode"],
                "object_id": _object_id(expected_b["device"], expected_b["inode"]),
            },
        },
        "workload": {"fd_a": fd_a, "fd_b": fd_b},
        "events": normalized_events,
    }
