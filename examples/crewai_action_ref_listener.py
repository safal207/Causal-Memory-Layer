"""Optional CrewAI listener that emits CML-compatible action_ref records."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cml.integrations.action_ref import (
    ACTION_REF_SCHEME,
    derive_action_ref,
    format_rfc3339_milliseconds_utc,
)

try:
    from crewai.events.base_event_listener import BaseEventListener
    from crewai.events.event_bus import CrewAIEventsBus
    from crewai.events.types.tool_usage_events import ToolUsageFinishedEvent
except ImportError:  # pragma: no cover
    BaseEventListener = object  # type: ignore[assignment,misc]
    CrewAIEventsBus = Any  # type: ignore[assignment,misc]
    ToolUsageFinishedEvent = Any  # type: ignore[assignment,misc]
    CREWAI_AVAILABLE = False
else:
    CREWAI_AVAILABLE = True

RecordSink = Callable[[dict[str, Any]], None]
ParentResolver = Callable[[Any, Any], str | None]
SessionResolver = Callable[[Any, Any], str | None]


def _event_agent_id(event: Any) -> str:
    return str(
        getattr(event, "agent_id", None)
        or getattr(event, "agent_role", None)
        or "unknown"
    )


def _event_timestamp(event: Any) -> str:
    started_at = getattr(event, "started_at", None)
    if started_at is None:
        raise ValueError("ToolUsageFinishedEvent.started_at is required")
    return format_rfc3339_milliseconds_utc(started_at)


def build_action_ref_record(
    event: Any,
    *,
    parent_action_ref: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Map a ToolUsageFinishedEvent-like object into a portable CML record."""

    tool_name = str(getattr(event, "tool_name", None) or "unknown_tool")
    task_id = getattr(event, "task_id", None)
    scope = str(task_id or "default")
    timestamp = _event_timestamp(event)
    action_ref = derive_action_ref(
        agent_id=_event_agent_id(event),
        action_type=tool_name,
        scope=scope,
        timestamp=timestamp,
    )
    finished_at = getattr(event, "finished_at", None)
    return {
        "action_id": action_ref,
        "action_ref": action_ref,
        "action_ref_scheme": ACTION_REF_SCHEME,
        "parent_action_id": None,
        "parent_action_ref": parent_action_ref,
        "session_id": session_id,
        "task_id": task_id,
        "timestamp": timestamp,
        "metadata": {
            "agent_id": _event_agent_id(event),
            "tool_name": tool_name,
            "finished_at": finished_at.isoformat() if finished_at else None,
            "from_cache": bool(getattr(event, "from_cache", False)),
        },
    }


if CREWAI_AVAILABLE:

    class ActionRefListener(BaseEventListener):
        def __init__(
            self,
            sink: RecordSink = print,
            parent_resolver: ParentResolver | None = None,
            session_resolver: SessionResolver | None = None,
        ) -> None:
            self._sink = sink
            self._parent_resolver = parent_resolver
            self._session_resolver = session_resolver

        def setup_listeners(self, crewai_event_bus: CrewAIEventsBus) -> None:
            @crewai_event_bus.on(ToolUsageFinishedEvent)
            def on_tool_finished(source: Any, event: ToolUsageFinishedEvent) -> None:
                parent_action_ref = (
                    self._parent_resolver(source, event)
                    if self._parent_resolver is not None
                    else None
                )
                session_id = (
                    self._session_resolver(source, event)
                    if self._session_resolver is not None
                    else None
                )
                self._sink(
                    build_action_ref_record(
                        event,
                        parent_action_ref=parent_action_ref,
                        session_id=session_id,
                    )
                )

else:

    class ActionRefListener:  # pragma: no cover
        def __init__(self, *_: Any, **__: Any) -> None:
            raise RuntimeError(
                "CrewAI is not installed. Install CrewAI to use ActionRefListener."
            )
