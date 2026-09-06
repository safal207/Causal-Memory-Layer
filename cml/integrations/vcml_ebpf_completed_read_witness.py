"""Completion-aware witnesses for vCML Linux eBPF read outcomes.

The v0.8 file monitor emits ``action == "read_exit"`` records from
``sys_exit_read``. Those records carry the kernel return value, a stable
boundary ``read_id``, and—when fd resolution succeeded—the kernel object
identity captured at ``sys_enter_read``.

Three projections intentionally coexist:

* ``CompletedReadWitness`` preserves the aggregate v0.6 contract;
* ``ExternalReadIdentityWitness`` exposes successful completion identities for
  exact ledger-coverage checks;
* ``ExternalReadObjectWitness`` binds each successful read identity to the
  kernel object that fd referenced at syscall entry.

The object projection does not claim exact pathname attribution. Paths in the
reference monitor remain descriptive userspace evidence. ``object_id`` is a
local kernel ``(device, inode)`` correlation identity, not a content hash or a
stable cross-host identity.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
from typing import Any

from cml.external_read_object_witness import (
    ExternalReadObjectBinding,
    ExternalReadObjectWitness,
)
from cml.external_read_witness import ExternalReadIdentityWitness, ExternalReadWitness


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
        """Project successful completions into the generic count contract."""

        return ExternalReadWitness(
            source_id=self.source_id,
            scope_id=self.scope_id,
            reads_count=self.completed_reads if self.available else 0,
            available=self.available,
        )


def _read_exit_object(record: Mapping[str, Any], *, index: int) -> Mapping[str, Any]:
    obj = record.get("object")
    if not isinstance(obj, Mapping):
        raise ValueError(f"read_exit record {index} must contain an object mapping")
    return obj


def _read_exit_return_value(record: Mapping[str, Any], *, index: int) -> int:
    obj = _read_exit_object(record, index=index)
    return_value = obj.get("return_value")
    if not isinstance(return_value, int) or isinstance(return_value, bool):
        raise ValueError(f"read_exit record {index} must contain integer return_value")
    return return_value


def _read_exit_id(record: Mapping[str, Any], *, index: int) -> str:
    read_id = record.get("read_id")
    if not isinstance(read_id, str) or not read_id.strip():
        raise ValueError(f"read_exit record {index} must contain non-empty read_id")
    return read_id


def _read_exit_object_id(record: Mapping[str, Any], *, index: int) -> str:
    obj = _read_exit_object(record, index=index)
    object_id = obj.get("object_id")
    if not isinstance(object_id, str) or not object_id.strip():
        raise ValueError(f"successful read_exit record {index} must contain non-empty object_id")
    return object_id


def completed_read_witness_from_vcml_records(
    records: Iterable[Mapping[str, Any]],
    *,
    scope_id: str,
    source_id: str = DEFAULT_COMPLETION_SOURCE_ID,
    available: bool = True,
) -> CompletedReadWitness:
    """Build aggregate completion evidence from vCML records.

    This legacy-compatible projection deliberately does not require ``read_id``
    or ``object_id``. Older v0.6/v0.7 JSONL streams therefore remain consumable.
    Use the identity or object projection when stronger evidence is required.
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

        return_value = _read_exit_return_value(record, index=index)
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


def completed_read_identity_witness_from_vcml_records(
    records: Iterable[Mapping[str, Any]],
    *,
    scope_id: str,
    source_id: str = DEFAULT_COMPLETION_SOURCE_ID,
    available: bool = True,
) -> ExternalReadIdentityWitness:
    """Build exact successful-read identity evidence from v0.7+ records.

    Every visible ``read_exit`` must carry a non-empty, unique ``read_id``. The
    syscall return value remains authoritative: ``ret >= 0`` contributes a
    completed identity (including EOF), while ``ret < 0`` is validated but not
    included in the successful-read coverage set.
    """

    if not available:
        return ExternalReadIdentityWitness(
            source_id=source_id,
            scope_id=scope_id,
            completed_read_ids=(),
            available=False,
        )

    completed_ids: list[str] = []
    seen_exit_ids: set[str] = set()

    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            raise TypeError(f"record {index} must be a mapping")
        if record.get("action") != "read_exit":
            continue

        return_value = _read_exit_return_value(record, index=index)
        read_id = _read_exit_id(record, index=index)
        if read_id in seen_exit_ids:
            raise ValueError(f"duplicate read_exit read_id: {read_id}")
        seen_exit_ids.add(read_id)

        if return_value >= 0:
            completed_ids.append(read_id)

    return ExternalReadIdentityWitness(
        source_id=source_id,
        scope_id=scope_id,
        completed_read_ids=tuple(completed_ids),
        available=True,
    )


def completed_read_object_witness_from_vcml_records(
    records: Iterable[Mapping[str, Any]],
    *,
    scope_id: str,
    source_id: str = DEFAULT_COMPLETION_SOURCE_ID,
    available: bool = True,
) -> ExternalReadObjectWitness:
    """Build successful read→kernel-object bindings from v0.8 records.

    ``read_id`` is required on every visible exit, matching the v0.7 identity
    contract. ``object_id`` is required only for successful completions because
    failed reads may legitimately have an unresolved/invalid fd. A successful
    exit without object identity fails closed instead of being downgraded to a
    vague fd/path claim.
    """

    if not available:
        return ExternalReadObjectWitness(
            source_id=source_id,
            scope_id=scope_id,
            completed_bindings=(),
            available=False,
        )

    completed_bindings: list[ExternalReadObjectBinding] = []
    seen_exit_ids: set[str] = set()

    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            raise TypeError(f"record {index} must be a mapping")
        if record.get("action") != "read_exit":
            continue

        return_value = _read_exit_return_value(record, index=index)
        read_id = _read_exit_id(record, index=index)
        if read_id in seen_exit_ids:
            raise ValueError(f"duplicate read_exit read_id: {read_id}")
        seen_exit_ids.add(read_id)

        if return_value >= 0:
            completed_bindings.append(
                ExternalReadObjectBinding(
                    read_id=read_id,
                    object_id=_read_exit_object_id(record, index=index),
                )
            )

    return ExternalReadObjectWitness(
        source_id=source_id,
        scope_id=scope_id,
        completed_bindings=tuple(completed_bindings),
        available=True,
    )


def _parse_vcml_jsonl(lines: Iterable[str | bytes]) -> list[Mapping[str, Any]]:
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
    return parsed


def completed_read_witness_from_vcml_jsonl(
    lines: Iterable[str | bytes],
    *,
    scope_id: str,
    source_id: str = DEFAULT_COMPLETION_SOURCE_ID,
    available: bool = True,
) -> CompletedReadWitness:
    """Parse JSONL fail-closed and build aggregate completion evidence."""

    if not available:
        return completed_read_witness_from_vcml_records(
            [],
            scope_id=scope_id,
            source_id=source_id,
            available=False,
        )
    return completed_read_witness_from_vcml_records(
        _parse_vcml_jsonl(lines),
        scope_id=scope_id,
        source_id=source_id,
        available=True,
    )


def completed_read_identity_witness_from_vcml_jsonl(
    lines: Iterable[str | bytes],
    *,
    scope_id: str,
    source_id: str = DEFAULT_COMPLETION_SOURCE_ID,
    available: bool = True,
) -> ExternalReadIdentityWitness:
    """Parse v0.7+ JSONL fail-closed and build exact completion identities."""

    if not available:
        return completed_read_identity_witness_from_vcml_records(
            [],
            scope_id=scope_id,
            source_id=source_id,
            available=False,
        )
    return completed_read_identity_witness_from_vcml_records(
        _parse_vcml_jsonl(lines),
        scope_id=scope_id,
        source_id=source_id,
        available=True,
    )


def completed_read_object_witness_from_vcml_jsonl(
    lines: Iterable[str | bytes],
    *,
    scope_id: str,
    source_id: str = DEFAULT_COMPLETION_SOURCE_ID,
    available: bool = True,
) -> ExternalReadObjectWitness:
    """Parse v0.8 JSONL fail-closed and build exact read→object bindings."""

    if not available:
        return completed_read_object_witness_from_vcml_records(
            [],
            scope_id=scope_id,
            source_id=source_id,
            available=False,
        )
    return completed_read_object_witness_from_vcml_records(
        _parse_vcml_jsonl(lines),
        scope_id=scope_id,
        source_id=source_id,
        available=True,
    )
