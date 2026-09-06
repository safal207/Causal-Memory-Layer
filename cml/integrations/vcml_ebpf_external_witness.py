"""Bridge vCML Linux eBPF read events into ``ExternalReadWitness``.

The current vCML file monitor emits ``action == \"read\"`` records from the
``sys_enter_read`` tracepoint. Those records prove that a read syscall boundary
was entered; they do not prove successful read completion because the return
value is not observed at syscall entry.

This adapter deliberately preserves that narrower meaning. It provides an
independent liveness witness for the admissibility layer without upgrading a
read attempt into a successful-read claim.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
from typing import Any

from cml.external_read_witness import ExternalReadWitness


DEFAULT_SOURCE_ID = "vcml-linux-ebpf:sys_enter_read"


def external_witness_from_vcml_records(
    records: Iterable[Mapping[str, Any]],
    *,
    scope_id: str,
    source_id: str = DEFAULT_SOURCE_ID,
    available: bool = True,
) -> ExternalReadWitness:
    """Count vCML read-boundary records into an external witness summary.

    ``reads_count`` means observed ``sys_enter_read`` boundary events for the
    supplied scope. Callers must not interpret it as the number of successful
    reads until a completion-aware monitor (for example, ``sys_exit_read``)
    supplies that stronger evidence.
    """

    if not available:
        return ExternalReadWitness(
            source_id=source_id,
            scope_id=scope_id,
            reads_count=0,
            available=False,
        )

    reads_count = 0
    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            raise TypeError(f"record {index} must be a mapping")
        if record.get("action") == "read":
            reads_count += 1

    return ExternalReadWitness(
        source_id=source_id,
        scope_id=scope_id,
        reads_count=reads_count,
        available=True,
    )


def external_witness_from_vcml_jsonl(
    lines: Iterable[str | bytes],
    *,
    scope_id: str,
    source_id: str = DEFAULT_SOURCE_ID,
    available: bool = True,
) -> ExternalReadWitness:
    """Parse vCML JSONL output and build an ``ExternalReadWitness``.

    Blank lines are ignored. Malformed JSON and non-object JSON records fail
    closed instead of silently reducing the witness count.
    """

    if not available:
        return ExternalReadWitness(
            source_id=source_id,
            scope_id=scope_id,
            reads_count=0,
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
            raise ValueError(
                f"invalid vCML JSONL at line {line_number}"
            ) from exc
        if not isinstance(record, dict):
            raise ValueError(
                f"vCML JSONL record at line {line_number} must be an object"
            )
        parsed.append(record)

    return external_witness_from_vcml_records(
        parsed,
        scope_id=scope_id,
        source_id=source_id,
        available=True,
    )
