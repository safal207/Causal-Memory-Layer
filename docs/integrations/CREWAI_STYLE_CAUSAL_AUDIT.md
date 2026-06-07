# CrewAI-style Causal Audit with CML

This note shows how a multi-agent workflow trace can be mapped into CML records and audited for broken causal lineage.

It is written as a **CrewAI-style** integration example, not as an official CrewAI integration.

## Why this matters

Agent frameworks can show that a task or tool call completed successfully.

CML asks a narrower audit question:

```text
Did this action have a valid causal permission / responsibility path?
```

This matters for multi-agent systems because an action may be operationally successful while still being causally invalid.

Example:

```text
assistant_agent sent an external email
but the referenced human approval / parent task is missing
```

In normal logs, this can look like a successful tool call.

In CML, this can be flagged as broken causal lineage.

## Example

Run:

```bash
pip install causal-memory-layer
python examples/crewai_style_causal_audit.py
```

Expected finding:

```text
CML-AUDIT-R1-MISSING_PARENT
```

## Trace shape

The demo builds this small workflow:

1. `approval-1`
   - human operator approves a research task;
   - root causal record.

2. `tool-call-search-1`
   - researcher agent performs a search;
   - valid parent: `approval-1`.

3. `task-write-summary-1`
   - analyst agent writes a summary;
   - valid parent: `tool-call-search-1`.

4. `tool-call-send-1`
   - assistant agent sends an external email;
   - invalid parent: `missing-human-approval`.

CML reports that the final action references a parent cause that does not exist in the trace.

## Mapping idea

A CrewAI-style event can be mapped into a CML record like this:

| Agent workflow concept | CML field |
|---|---|
| agent / role | `actor.comm` |
| task id / tool call id | `id` |
| tool action | `action` |
| task/tool payload | `object` |
| approval / task permission | `permitted_by` |
| upstream task / approval id | `parent_cause` |

## Minimal code shape

```python
from cml.audit import AuditEngine
from cml.record import Actor, CausalRecord

records = [
    CausalRecord(
        id="approval-1",
        timestamp=1,
        actor=Actor(pid=100, uid=1000, comm="human_operator"),
        action="approve_task",
        object={"task": "research"},
        permitted_by="root_event:human_approved_research_goal",
        parent_cause=None,
    ),
    CausalRecord(
        id="tool-call-send-1",
        timestamp=2,
        actor=Actor(pid=101, uid=1000, comm="assistant_agent"),
        action="send",
        object={"tool": "email"},
        permitted_by="task:external_send",
        parent_cause="missing-human-approval",
    ),
]

result = AuditEngine().run(records)
print(result.to_dict())
```

## Non-claims

This example does not claim that CML provides:

- production AI safety,
- policy enforcement,
- regulatory compliance,
- complete security coverage,
- complete jailbreak detection,
- stable Cause Band semantics.

The narrow claim is:

```text
CML can provide a lightweight causal-validity audit over structured agent action traces.
```

## Related links

- PyPI: https://pypi.org/project/causal-memory-layer/
- GitHub release: https://github.com/safal207/Causal-Memory-Layer/releases/tag/v0.4.0
- Production install smoke test: https://github.com/safal207/Causal-Memory-Layer/actions/runs/27101272184/job/79982287069
- CrewAI outreach issue: https://github.com/crewAIInc/crewAI/issues/6063
