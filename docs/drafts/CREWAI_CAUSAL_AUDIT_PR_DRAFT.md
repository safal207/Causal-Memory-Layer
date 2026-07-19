# Draft PR: optional causal audit example for agent action traces

Target repository:

```text
crewAIInc/crewAI
```

Suggested title:

```text
docs: add optional causal audit example for agent action traces
```

## Summary

This draft proposes a small optional docs/example contribution showing how a CrewAI-style agent/task/tool trace could be mapped into structured causal records and audited for broken lineage.

The goal is intentionally narrow:

> Detect actions that completed operationally but reference a missing or malformed upstream task, approval, or responsibility parent.

This is documentation/example-only.

It does not change CrewAI core execution logic.

## Why this matters

Agent frameworks can show that a task or tool call happened.

However, a successful action log does not always answer a separate audit question:

```text
Did this action have a valid causal permission / responsibility path?
```

Example:

```text
assistant_agent sends an external message
but the referenced parent task / human approval is missing
```

From a tracing perspective, the tool call may look successful.

From a causal-audit perspective, the action has broken lineage.

This example demonstrates a lightweight pattern for making that gap inspectable.

## What the example does

The example:

1. defines a tiny CrewAI-style action trace;
2. maps `parent_action_id` to a causal parent field;
3. runs a lightweight audit pass over the structured records;
4. reports a broken lineage case when a parent reference is missing.

Expected finding:

```text
CML-AUDIT-R1-MISSING_PARENT
```

## Minimal trace shape

A CrewAI-style event could look like this:

```python
{
    "id": "tool-call-send-1",
    "agent": "assistant_agent",
    "action": "send",
    "object": {
        "tool": "email",
        "recipient": "external@example.com"
    },
    "permitted_by": "task:assistant_agent_external_send",
    "parent_action_id": "missing-human-approval"
}
```

The key mapping is:

```text
parent_action_id -> parent_cause
```

## Suggested mapping

| CrewAI-style concept | Causal audit field |
|---|---|
| agent / role | actor |
| task id / tool call id | id |
| tool action | action |
| task/tool payload | object |
| upstream task / approval id | parent_cause |
| permission / task reason | permitted_by |

## Scope

This proposal is intentionally limited to:

- documentation;
- a standalone example;
- no CrewAI core changes;
- no runtime blocking;
- no policy enforcement;
- no compliance or safety certification claims.

## Non-goals

This example does not claim to provide:

- production AI safety;
- policy enforcement;
- regulatory compliance;
- complete observability;
- complete security coverage;
- jailbreak detection.

The narrow claim is only:

```text
A structured agent action trace can be audited for causal validity.
```

## Suggested files for a CrewAI PR

```text
docs/examples/causal_action_trace_audit.md
examples/causal_action_trace_audit.py
```

## Draft example file

```python
"""Optional causal audit example for agent action traces.

This example demonstrates a small docs-only pattern:

1. represent an agent/task/tool trace as structured events;
2. map parent_action_id to parent_cause;
3. audit the trace for broken causal lineage.

It does not import CrewAI.
It does not change CrewAI execution behavior.
It does not enforce policy or block runtime execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentAction:
    id: str
    agent: str
    action: str
    object: dict[str, Any]
    permitted_by: str
    parent_action_id: str | None = None


@dataclass(frozen=True)
class AuditFinding:
    code: str
    record_id: str
    message: str


def make_trace() -> list[AgentAction]:
    """Build a tiny agent trace with one broken parent reference."""

    return [
        AgentAction(
            id="task-root-1",
            agent="human_operator",
            action="approve_task",
            object={"task": "prepare research summary"},
            permitted_by="root_event:user_requested_summary",
            parent_action_id=None,
        ),
        AgentAction(
            id="tool-call-search-1",
            agent="research_agent",
            action="search",
            object={"query": "agent auditability patterns"},
            permitted_by="task:research_summary",
            parent_action_id="task-root-1",
        ),
        AgentAction(
            id="task-write-summary-1",
            agent="writer_agent",
            action="write",
            object={"artifact": "summary.md"},
            permitted_by="task:write_summary",
            parent_action_id="tool-call-search-1",
        ),
        AgentAction(
            id="tool-call-send-1",
            agent="assistant_agent",
            action="send",
            object={
                "tool": "email",
                "recipient": "external@example.com",
            },
            permitted_by="task:send_summary",
            parent_action_id="missing-human-approval",
        ),
    ]


def audit_missing_parents(trace: list[AgentAction]) -> list[AuditFinding]:
    """Report actions whose parent_action_id does not exist in the trace."""

    known_ids = {event.id for event in trace}
    findings: list[AuditFinding] = []

    for event in trace:
        if event.parent_action_id is None:
            continue

        if event.parent_action_id not in known_ids:
            findings.append(
                AuditFinding(
                    code="CML-AUDIT-R1-MISSING_PARENT",
                    record_id=event.id,
                    message=(
                        f"Action {event.id!r} references missing parent "
                        f"{event.parent_action_id!r}."
                    ),
                )
            )

    return findings


def main() -> None:
    trace = make_trace()
    findings = audit_missing_parents(trace)

    print("Causal audit result")

    if not findings:
        print("PASS: no broken causal lineage detected.")
        return

    print("Broken causal lineage detected:")
    for finding in findings:
        print(f"- {finding.code}: {finding.message}")


if __name__ == "__main__":
    main()
```

## Related context

Existing discussion:

```text
https://github.com/crewAIInc/crewAI/issues/6063
```

Standalone CML prototype:

```text
https://github.com/safal207/Causal-Memory-Layer/blob/main/examples/crewai_style_causal_audit.py
https://github.com/safal207/Causal-Memory-Layer/blob/main/docs/integrations/CREWAI_STYLE_CAUSAL_AUDIT.md
```

## Validation

Not run locally in this draft.

The proposed example is intentionally small and can be validated by checking that the broken parent reference produces the expected missing-parent audit finding.
