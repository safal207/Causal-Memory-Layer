"""Per-read coverage reconciliation for vCML boundary-generated read identities.

The v0.7 file monitor emits the same top-level ``read_id`` on ``read`` and
``read_exit`` records. Successful external completions can therefore be matched
to downstream ledger observations by identity rather than by aggregate count.

Coverage invariant:

    ExternalSuccessfulReadIds ⊆ LedgerObservedReadIds

Extra ledger ids are reported for diagnostics but do not make this coverage
predicate fail. Duplicate ledger ids are also surfaced so replay/duplication
cannot be hidden by set projection.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
from typing import Any


@dataclass(frozen=True)
class ReadIdCoverageResult:
    """Result of per-read coverage reconciliation for one caller-defined scope."""

    scope_id: str
    applicable: bool
    holds: bool
    external_successful_read_ids: tuple[str, ...]
    ledger_observed_read_ids: tuple[str, ...]
    missing_read_ids: tuple[str, ...]
    unexpected_ledger_read_ids: tuple[str, ...]
    duplicate_ledger_read_ids: tuple[str, ...]
    reasons: tuple[str, ...] = ()

    @property
    def covered_count(self) -> int:
        return len(self.external_successful_read_ids) - len(self.missing_read_ids)


def _require_scope_id(scope_id: str) -> None:
    if not isinstance(scope_id, str) or not scope_id.strip():
        raise ValueError("scope_id must be a non-empty string")


def _read_id_from_record(record: Mapping[str, Any], *, label: str) -> str:
    read_id = record.get("read_id")
    if not isinstance(read_id, str) or not read_id.strip():
        raise ValueError(f"{label} must contain a non-empty read_id")
    return read_id


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object while rejecting authority-ambiguous names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reconcile_successful_read_id_coverage(
    external_records: Iterable[Mapping[str, Any]],
    ledger_observations: Iterable[Mapping[str, Any]],
    *,
    scope_id: str,
    external_available: bool = True,
) -> ReadIdCoverageResult:
    """Reconcile successful external read completions against ledger read ids.

    External records are expected to be the vCML boundary stream. Only
    ``action == "read_exit"`` records whose kernel ``return_value >= 0`` require
    downstream coverage. Failed reads are intentionally excluded.

    Ledger observations are expected to be pre-scoped observations of the same
    successful-read semantic and every supplied observation must carry a
    ``read_id``. The function does not silently infer or manufacture ids.
    """

    _require_scope_id(scope_id)
    if not isinstance(external_available, bool):
        raise TypeError("external_available must be boolean")

    if not external_available:
        return ReadIdCoverageResult(
            scope_id=scope_id,
            applicable=False,
            holds=False,
            external_successful_read_ids=(),
            ledger_observed_read_ids=(),
            missing_read_ids=(),
            unexpected_ledger_read_ids=(),
            duplicate_ledger_read_ids=(),
            reasons=("external_witness_unavailable",),
        )

    external_ids: list[str] = []
    external_seen: set[str] = set()

    for index, record in enumerate(external_records, start=1):
        if not isinstance(record, Mapping):
            raise TypeError(f"external record {index} must be a mapping")
        if record.get("action") != "read_exit":
            continue

        obj = record.get("object")
        if not isinstance(obj, Mapping):
            raise ValueError(f"read_exit record {index} must contain an object mapping")
        return_value = obj.get("return_value")
        if not isinstance(return_value, int) or isinstance(return_value, bool):
            raise ValueError(f"read_exit record {index} must contain integer return_value")
        if return_value < 0:
            continue

        read_id = _read_id_from_record(record, label=f"successful read_exit record {index}")
        if read_id in external_seen:
            raise ValueError(f"duplicate successful external read_id: {read_id}")
        external_seen.add(read_id)
        external_ids.append(read_id)

    ledger_ids: list[str] = []
    for index, observation in enumerate(ledger_observations, start=1):
        if not isinstance(observation, Mapping):
            raise TypeError(f"ledger observation {index} must be a mapping")
        ledger_ids.append(
            _read_id_from_record(observation, label=f"ledger observation {index}")
        )

    external_set = set(external_ids)
    ledger_set = set(ledger_ids)
    ledger_counts = Counter(ledger_ids)

    missing = tuple(sorted(external_set - ledger_set))
    unexpected = tuple(sorted(ledger_set - external_set))
    duplicate_ledger = tuple(sorted(read_id for read_id, count in ledger_counts.items() if count > 1))

    if not external_ids:
        return ReadIdCoverageResult(
            scope_id=scope_id,
            applicable=False,
            holds=False,
            external_successful_read_ids=(),
            ledger_observed_read_ids=tuple(sorted(ledger_set)),
            missing_read_ids=(),
            unexpected_ledger_read_ids=unexpected,
            duplicate_ledger_read_ids=duplicate_ledger,
            reasons=("coverage_not_exercised",),
        )

    reasons = ("missing_ledger_observations",) if missing else ()
    return ReadIdCoverageResult(
        scope_id=scope_id,
        applicable=True,
        holds=not missing,
        external_successful_read_ids=tuple(sorted(external_set)),
        ledger_observed_read_ids=tuple(sorted(ledger_set)),
        missing_read_ids=missing,
        unexpected_ledger_read_ids=unexpected,
        duplicate_ledger_read_ids=duplicate_ledger,
        reasons=reasons,
    )


def reconcile_successful_read_id_coverage_jsonl(
    external_lines: Iterable[str | bytes],
    ledger_lines: Iterable[str | bytes],
    *,
    scope_id: str,
    external_available: bool = True,
) -> ReadIdCoverageResult:
    """Parse both JSONL streams fail-closed and reconcile by read identity."""

    def parse(lines: Iterable[str | bytes], *, stream_name: str) -> list[Mapping[str, Any]]:
        parsed: list[Mapping[str, Any]] = []
        for line_number, line in enumerate(lines, start=1):
            if isinstance(line, bytes):
                try:
                    line = line.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError(
                        f"invalid UTF-8 in {stream_name} JSONL at line {line_number}"
                    ) from exc
            if not isinstance(line, str):
                raise TypeError(f"{stream_name} line {line_number} must be str or bytes")

            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text, object_pairs_hook=_unique_json_object)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid {stream_name} JSONL at line {line_number}"
                ) from exc
            if not isinstance(record, dict):
                raise ValueError(
                    f"{stream_name} JSONL record at line {line_number} must be an object"
                )
            parsed.append(record)
        return parsed

    return reconcile_successful_read_id_coverage(
        parse(external_lines, stream_name="external"),
        parse(ledger_lines, stream_name="ledger"),
        scope_id=scope_id,
        external_available=external_available,
    )
