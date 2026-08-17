"""Completion-aware witness for vCML Linux eBPF read outcomes.

The v0.6 file monitor emits ``action == "read_exit"`` records from
``sys_exit_read``. Those records carry the kernel return value and therefore
allow consumers to distinguish:

* successful completion with bytes returned (ret > 0),
* successful EOF / zero-byte completion (ret == 0), and
* failed completion (ret < 0).

This module remains aggregate-only. It summarizes the observed stream but does
not claim exact per-read coverage because the current JSONL contract does not
carry a stable boundary-generated read id across entry and exit records.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
from typing import Any

from cml.external_read_witness import ExternalReadWitness


DEFAULT_COMPLETION_SOURCE_ID = "vcml-linux-ebpf:sys_exit_read"


@dataclass(frozen=True)
class CompletedReadWitness:
    """Aggregate evidence from read entry and read exit boundary records."""

    source_id: str
    scope_id: str
    attempts_seen: int
    exit_events_seen: int
    completed_reads: int
    zero_byte_reads: int
    failed_reads: int
    bytes_returned: int
    available: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise ValueError("source_id must be a non-empty string")
        if not isinstance(self.scope_id, str) or not self.scope_id.strip():
            raise ValueError("scope_id must be a non-empty string")
        for name in (
            "attempts_seen",
            "exit_events_seen",
            "completed_reads",
            "zero_byte_reads",
            "failed_reads",
            "bytes_returned",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")
            if value < 0:
                raise ValueError(f"{name} must be non-negative")
        if not isinstance(self.available, bool):
            raise TypeError("available must be boolean")
        if self.completed_reads + self.failed_reads != self.exit_events_seen:
            raise ValueError("completed_reads + failed_reads must equal exit_events_seen")
        if self.zero_byte_reads > self.completed_reads:
            raise ValueError("zero_byte_reads cannot exceed completed_reads")

    def as_completed_external_witness(self) -> ExternalReadWitness:
        """Project successful completions into the generic witness contract.

        This projection is appropriate only when the downstream ledger count
        represents successful read completions too. It must not be compared
        blindly with a ledger that records read attempts instead.
        """

        return ExternalReadWitness(
            source_id=self.source_id,
            scope_id=self.scope_id,
            reads_count=self.completed_reads if self.available else 0,
            available=self.available,
        )


def completed_read_witness_from_vcml_records(
    records: Iterable[Mapping[str, Any]],
    *,
    scope_id: str,
    source_id: str = DEFAULT_COMPLETION_SOURCE_ID,
    available: bool = True,
) -> CompletedReadWitness:
    """Build aggregate completion evidence from vCML records.

    ``action == "read"`` contributes only to ``attempts_seen``.
    ``action == "read_exit"`` contributes outcome evidence. The return value is
    authoritative for classification; any redundant textual status is ignored.
    """

    if not available:
        return CompletedReadWitness(
            source_id=source_id,
            scope_id=scope_id,
            attempts_seen=0,
            exit_events_seen=0,
            completed_reads=0,
            zero_byte_reads=0,
            failed_reads=0,
            bytes_returned=0,
            available=False,
        )

    attempts_seen = 0
    exit_events_seen = 0
    completed_reads = 0
    zero_byte_reads = 0
    failed_reads = 0
    bytes_returned = 0

    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            raise TypeError(f"record {index} must be a mapping")

        action = record.get("action")
        if action == "read":
            attempts_seen += 1
            continue
        if action != "read_exit":
            continue

        obj = record.get("object")
        if not isinstance(obj, Mapping):
            raise ValueError(f"read_exit record {index} must contain an object mapping")
        return_value = obj.get("return_value")
        if not isinstance(return_value, int) or isinstance(return_value, bool):
            raise ValueError(f"read_exit record {index} must contain integer return_value")

        exit_events_seen += 1
        if return_value >= 0:
            completed_reads += 1
            if return_value == 0:
                zero_byte_reads += 1
            else:
                bytes_returned += return_value
        else:
            failed_reads += 1

    return CompletedReadWitness(
        source_id=source_id,
        scope_id=scope_id,
        attempts_seen=attempts_seen,
        exit_events_seen=exit_events_seen,
        completed_reads=completed_reads,
        zero_byte_reads=zero_byte_reads,
        failed_reads=failed_reads,
        bytes_returned=bytes_returned,
        available=True,
    )


def completed_read_witness_from_vcml_jsonl(
    lines: Iterable[str | bytes],
    *,
    scope_id: str,
    source_id: str = DEFAULT_COMPLETION_SOURCE_ID,
    available: bool = True,
) -> CompletedReadWitness:
    """Parse JSONL fail-closed and build completion-aware read evidence."""

    if not available:
        return completed_read_witness_from_vcml_records(
            [],
            scope_id=scope_id,
            source_id=source_id,
            available=False,
        )

    parsed: list[Mapping[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"invalid UTF-8 in vCML JSONL at line {line_number}"
                ) from exc
        if not isinstance(line, str):
            raise TypeError(f"line {line_number} must be str or bytes")

        text = line.strip()
        if not text:
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid vCML JSONL at line {line_number}") from exc
        if not isinstance(record, dict):
            raise ValueError(
                f"vCML JSONL record at line {line_number} must be an object"
            )
        parsed.append(record)

    return completed_read_witness_from_vcml_records(
        parsed,
        scope_id=scope_id,
        source_id=source_id,
        available=True,
    )
