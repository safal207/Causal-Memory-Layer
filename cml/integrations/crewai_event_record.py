"""Read-only structural audit for CrewAI ``RuntimeState.event_record``.

The adapter intentionally does not import CrewAI. It accepts the serialized shape
of ``EventRecord`` or event-like Python objects and validates the relationship
fields already emitted by CrewAI.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

REFERENCE_FIELDS = (
    "parent_event_id",
    "previous_event_id",
    "triggered_by_event_id",
    "started_event_id",
)

# Mirrored from CrewAI's current event lifecycle pairs. Keeping the mapping local
# makes the audit adapter dependency-free and usable against serialized records.
CREWAI_EVENT_PAIRS: Mapping[str, str] = {
    "flow_finished": "flow_started",
    "flow_paused": "flow_started",
    "method_execution_finished": "method_execution_started",
    "method_execution_failed": "method_execution_started",
    "method_execution_paused": "method_execution_started",
    "crew_kickoff_completed": "crew_kickoff_started",
    "crew_kickoff_failed": "crew_kickoff_started",
    "crew_train_completed": "crew_train_started",
    "crew_train_failed": "crew_train_started",
    "crew_test_completed": "crew_test_started",
    "crew_test_failed": "crew_test_started",
    "agent_execution_completed": "agent_execution_started",
    "agent_execution_error": "agent_execution_started",
    "agent_evaluation_completed": "agent_evaluation_started",
    "agent_evaluation_failed": "agent_evaluation_started",
    "lite_agent_execution_completed": "lite_agent_execution_started",
    "lite_agent_execution_error": "lite_agent_execution_started",
    "task_completed": "task_started",
    "task_failed": "task_started",
    "llm_call_completed": "llm_call_started",
    "llm_call_failed": "llm_call_started",
    "llm_guardrail_completed": "llm_guardrail_started",
    "llm_guardrail_failed": "llm_guardrail_started",
    "tool_usage_finished": "tool_usage_started",
    "tool_usage_error": "tool_usage_started",
    "mcp_connection_completed": "mcp_connection_started",
    "mcp_connection_failed": "mcp_connection_started",
    "mcp_tool_execution_completed": "mcp_tool_execution_started",
    "mcp_tool_execution_failed": "mcp_tool_execution_started",
    "memory_retrieval_completed": "memory_retrieval_started",
    "memory_retrieval_failed": "memory_retrieval_started",
    "memory_save_completed": "memory_save_started",
    "memory_save_failed": "memory_save_started",
    "memory_query_completed": "memory_query_started",
    "memory_query_failed": "memory_query_started",
    "knowledge_query_completed": "knowledge_query_started",
    "knowledge_query_failed": "knowledge_query_started",
    "knowledge_search_query_completed": "knowledge_search_query_started",
    "knowledge_search_query_failed": "knowledge_search_query_started",
    "a2a_delegation_completed": "a2a_delegation_started",
    "a2a_conversation_completed": "a2a_conversation_started",
    "a2a_server_task_completed": "a2a_server_task_started",
    "a2a_server_task_canceled": "a2a_server_task_started",
    "a2a_server_task_failed": "a2a_server_task_started",
    "a2a_parallel_delegation_completed": "a2a_parallel_delegation_started",
    "agent_reasoning_completed": "agent_reasoning_started",
    "agent_reasoning_failed": "agent_reasoning_started",
}


@dataclass(frozen=True)
class CrewAIEventSnapshot:
    """Dependency-free projection of the CrewAI event relationship fields."""

    event_id: str
    event_type: str
    parent_event_id: str | None = None
    previous_event_id: str | None = None
    triggered_by_event_id: str | None = None
    started_event_id: str | None = None
    emission_sequence: int | None = None


@dataclass(frozen=True)
class CrewAIEventRecordFinding:
    """A deterministic structural finding for one CrewAI event."""

    code: str
    event_id: str
    message: str
    field: str | None = None
    referenced_event_id: str | None = None


@dataclass(frozen=True)
class CrewAIEventRecordValidationResult:
    """Validation result returned by :func:`validate_crewai_event_record`."""

    findings: tuple[CrewAIEventRecordFinding, ...]

    def passed(self) -> bool:
        return not self.findings


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _event_from_node(value: Any) -> Any:
    event = _field(value, "event")
    return event if event is not None else value


def _snapshot(value: Any) -> CrewAIEventSnapshot:
    event = _event_from_node(value)
    event_id = _field(event, "event_id")
    event_type = _field(event, "type")
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("CrewAI event_id must be a non-empty string")
    if not isinstance(event_type, str) or not event_type:
        raise ValueError(f"CrewAI event {event_id!r} must have a non-empty type")

    references: dict[str, str | None] = {}
    for field_name in REFERENCE_FIELDS:
        reference = _field(event, field_name)
        if reference is not None and (not isinstance(reference, str) or not reference):
            raise ValueError(
                f"CrewAI event {event_id!r} field {field_name} must be null "
                "or a non-empty string"
            )
        references[field_name] = reference

    return CrewAIEventSnapshot(
        event_id=event_id,
        event_type=event_type,
        emission_sequence=_field(event, "emission_sequence"),
        **references,
    )


def snapshots_from_crewai_event_record(value: Any) -> tuple[CrewAIEventSnapshot, ...]:
    """Project a CrewAI EventRecord, serialized record, or event iterable.

    Supported inputs:

    * an object with a ``nodes`` mapping;
    * a mapping containing ``{"nodes": ...}``;
    * an iterable of event-like objects or serialized event mappings.
    """

    nodes = _field(value, "nodes")
    if isinstance(nodes, Mapping):
        raw_events = list(nodes.values())
    elif isinstance(value, Iterable) and not isinstance(value, (str, bytes, Mapping)):
        raw_events = list(value)
    else:
        raise TypeError(
            "value must be a CrewAI EventRecord-like object, serialized record, "
            "or iterable of events"
        )
    return tuple(_snapshot(event) for event in raw_events)


def _finding(
    *,
    code: str,
    event: CrewAIEventSnapshot,
    message: str,
    field: str | None = None,
    referenced_event_id: str | None = None,
) -> CrewAIEventRecordFinding:
    return CrewAIEventRecordFinding(
        code=code,
        event_id=event.event_id,
        field=field,
        referenced_event_id=referenced_event_id,
        message=message,
    )


def _snapshot_sort_key(event: CrewAIEventSnapshot) -> tuple[Any, ...]:
    """Return an input-order-independent key for duplicate canonicalization."""

    sequence = event.emission_sequence
    sequence_key: tuple[int, int | str]
    if isinstance(sequence, int) and not isinstance(sequence, bool):
        sequence_key = (0, sequence)
    else:
        sequence_key = (1, repr(sequence))
    return (
        event.event_id,
        event.event_type,
        event.parent_event_id or "",
        event.previous_event_id or "",
        event.triggered_by_event_id or "",
        event.started_event_id or "",
        sequence_key,
    )


def validate_crewai_event_record(value: Any) -> CrewAIEventRecordValidationResult:
    """Validate CrewAI's existing event graph without changing execution.

    The audit checks duplicate IDs, unresolved typed references, orphaned roots,
    lifecycle pairing, reference cycles, and emission ordering. It does not
    enforce policy, block execution, sign records, or mutate ``EventRecord``.
    """

    events = snapshots_from_crewai_event_record(value)
    findings: list[CrewAIEventRecordFinding] = []
    grouped_by_id: dict[str, list[CrewAIEventSnapshot]] = {}

    for event in events:
        grouped_by_id.setdefault(event.event_id, []).append(event)

    by_id: dict[str, CrewAIEventSnapshot] = {}
    for event_id in sorted(grouped_by_id):
        variants = sorted(grouped_by_id[event_id], key=_snapshot_sort_key)
        by_id[event_id] = variants[0]
        for duplicate in variants[1:]:
            findings.append(
                _finding(
                    code="CML-CREWAI-DUPLICATE-EVENT-ID",
                    event=duplicate,
                    message=f"duplicate event_id: {event_id}",
                )
            )

    # Local reference and lifecycle checks run across every variant so a
    # non-canonical duplicate cannot hide a structural defect. Graph-wide
    # checks use the deterministic canonical snapshot selected above.
    for event in sorted(events, key=_snapshot_sort_key):
        for field_name in REFERENCE_FIELDS:
            referenced_id = getattr(event, field_name)
            if referenced_id is None or referenced_id in by_id:
                continue
            code = (
                "CML-CREWAI-ORPHANED-ROOT"
                if field_name == "parent_event_id"
                else "CML-CREWAI-MISSING-REFERENCE"
            )
            findings.append(
                _finding(
                    code=code,
                    event=event,
                    field=field_name,
                    referenced_event_id=referenced_id,
                    message=f"{field_name} does not resolve: {referenced_id}",
                )
            )

        expected_start_type = CREWAI_EVENT_PAIRS.get(event.event_type)
        if expected_start_type is not None:
            started_id = event.started_event_id
            if started_id is None:
                findings.append(
                    _finding(
                        code="CML-CREWAI-PAIR-MISMATCH",
                        event=event,
                        field="started_event_id",
                        message=(
                            f"{event.event_type} must reference a "
                            f"{expected_start_type} event"
                        ),
                    )
                )
            elif started_id in by_id:
                actual_start_type = by_id[started_id].event_type
                if actual_start_type != expected_start_type:
                    findings.append(
                        _finding(
                            code="CML-CREWAI-PAIR-MISMATCH",
                            event=event,
                            field="started_event_id",
                            referenced_event_id=started_id,
                            message=(
                                f"{event.event_type} started_event_id resolves to "
                                f"{actual_start_type}, expected {expected_start_type}"
                            ),
                        )
                    )

    sequence_groups: dict[int, list[CrewAIEventSnapshot]] = {}
    valid_sequences: dict[str, int] = {}
    for event in sorted(by_id.values(), key=_snapshot_sort_key):
        sequence = event.emission_sequence
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
            findings.append(
                _finding(
                    code="CML-CREWAI-SEQUENCE-VIOLATION",
                    event=event,
                    field="emission_sequence",
                    message="emission_sequence must be a positive integer",
                )
            )
            continue
        valid_sequences[event.event_id] = sequence
        sequence_groups.setdefault(sequence, []).append(event)

    for sequence in sorted(sequence_groups):
        owners = sorted(sequence_groups[sequence], key=lambda item: item.event_id)
        canonical_owner = owners[0]
        for duplicate_owner in owners[1:]:
            findings.append(
                _finding(
                    code="CML-CREWAI-SEQUENCE-VIOLATION",
                    event=duplicate_owner,
                    field="emission_sequence",
                    referenced_event_id=canonical_owner.event_id,
                    message=(
                        f"emission_sequence {sequence} is already used by "
                        f"{canonical_owner.event_id}"
                    ),
                )
            )

    for event in sorted(by_id.values(), key=lambda item: item.event_id):
        current_sequence = valid_sequences.get(event.event_id)
        if current_sequence is None:
            continue
        for field_name in REFERENCE_FIELDS:
            referenced_id = getattr(event, field_name)
            referenced_sequence = valid_sequences.get(referenced_id or "")
            if referenced_sequence is None:
                continue
            if referenced_sequence >= current_sequence:
                findings.append(
                    _finding(
                        code="CML-CREWAI-SEQUENCE-VIOLATION",
                        event=event,
                        field=field_name,
                        referenced_event_id=referenced_id,
                        message=(
                            f"{field_name} must reference an earlier event: "
                            f"{referenced_sequence} >= {current_sequence}"
                        ),
                    )
                )

    state: dict[str, int] = {}
    reported_edges: set[tuple[str, str, str]] = set()

    for start_id in sorted(by_id):
        if state.get(start_id, 0) != 0:
            continue
        state[start_id] = 1
        stack: list[tuple[str, int]] = [(start_id, 0)]

        while stack:
            event_id, field_index = stack[-1]
            if field_index >= len(REFERENCE_FIELDS):
                state[event_id] = 2
                stack.pop()
                continue

            field_name = REFERENCE_FIELDS[field_index]
            stack[-1] = (event_id, field_index + 1)
            event = by_id[event_id]
            referenced_id = getattr(event, field_name)
            if referenced_id is None or referenced_id not in by_id:
                continue

            referenced_state = state.get(referenced_id, 0)
            if referenced_state == 0:
                state[referenced_id] = 1
                stack.append((referenced_id, 0))
            elif referenced_state == 1:
                edge = (event_id, field_name, referenced_id)
                if edge not in reported_edges:
                    findings.append(
                        _finding(
                            code="CML-CREWAI-CYCLE",
                            event=event,
                            field=field_name,
                            referenced_event_id=referenced_id,
                            message=(
                                f"cycle detected through {field_name}: "
                                f"{event_id} -> {referenced_id}"
                            ),
                        )
                    )
                    reported_edges.add(edge)

    unique_findings = sorted(
        set(findings),
        key=lambda item: (
            item.code,
            item.event_id,
            item.field or "",
            item.referenced_event_id or "",
            item.message,
        ),
    )
    return CrewAIEventRecordValidationResult(findings=tuple(unique_findings))
