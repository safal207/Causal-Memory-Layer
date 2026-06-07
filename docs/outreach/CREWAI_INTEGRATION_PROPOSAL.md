# CrewAI Integration Proposal — CML Causal Audit for Agent Traces

## Target project

```text
crewAIInc/crewAI
```

Repo:

```text
https://github.com/crewAIInc/crewAI
```

## Why CrewAI

CrewAI is a strong first outreach target because:

- it is Python-first;
- it focuses on agents, crews, flows, tasks, tools, and multi-agent workflows;
- CML is now available as a normal PyPI package;
- the integration can start as a small optional example, not a core dependency.

## Current CML evidence

```text
PyPI: https://pypi.org/project/causal-memory-layer/0.4.0/
GitHub release: https://github.com/safal207/Causal-Memory-Layer/releases/tag/v0.4.0
Install: pip install causal-memory-layer==0.4.0
Production smoke test: https://github.com/safal207/Causal-Memory-Layer/actions/runs/27101272184/job/79982287069
```

## Contribution note

CrewAI contributing guidelines require AI-generated issues/PRs to use the `llm-generated` label.

If we create an issue or PR with AI assistance, add the label:

```text
llm-generated
```

## Recommended first move

Open a lightweight issue or discussion asking whether maintainers would be open to a small optional docs/example PR.

Do not start by adding CML as a dependency to CrewAI core.

Recommended scope:

```text
optional example / docs integration only
```

Potential example path:

```text
docs/en/examples/cml_causal_audit_for_agent_traces.mdx
```

or similar, depending on maintainer preference.

## Proposed issue title

```text
Example proposal: optional causal audit for agent action traces
```

## Proposed issue body

```markdown
Hi CrewAI maintainers,

I’m exploring a small optional integration idea around agent workflow auditability.

I maintain `causal-memory-layer`, a small Python package for checking causal validity in structured action traces:

- PyPI: https://pypi.org/project/causal-memory-layer/
- GitHub: https://github.com/safal207/Causal-Memory-Layer
- Install: `pip install causal-memory-layer`
- Release: https://github.com/safal207/Causal-Memory-Layer/releases/tag/v0.4.0

The narrow use case is not policy enforcement, production safety certification, or compliance. It is a lightweight audit primitive:

> Given a sequence of agent/tool actions, can we detect actions that succeeded operationally but lack a valid parent cause, approval, or responsibility lineage?

Example failure mode:

1. A crew/task/tool action is recorded as completed.
2. The action references a parent cause, approval id, or upstream responsibility claim.
3. That referenced parent cause is missing or malformed.
4. CML reports broken causal lineage.

This is different from observability/tracing: tracing can show what happened, while CML checks whether the action had a valid causal permission/responsibility path.

Would you be open to a small docs/example PR showing how to convert a simple CrewAI-style workflow trace into CML records and run a causal audit over it?

I would keep it:

- optional,
- dependency-light,
- outside CrewAI core,
- framed as an example only,
- with explicit non-claims.

If this is better suited for Discussions rather than Issues, I’m happy to move it there.

Note: this issue was drafted with AI assistance, so it should be labeled `llm-generated` according to the CrewAI contribution guidelines.
```

## Proposed minimal example shape

```python
from cml import AuditEngine
from cml.record import CausalRecord

records = [
    CausalRecord.from_dict(
        {
            "event_id": "approval-1",
            "action": "human_approval",
            "actor": "operator",
            "parent_event_id": None,
            "metadata": {"reason": "approve research task"},
        }
    ),
    CausalRecord.from_dict(
        {
            "event_id": "tool-call-1",
            "action": "run_tool",
            "actor": "researcher_agent",
            "parent_event_id": "approval-1",
            "metadata": {"tool": "web_search"},
        }
    ),
    CausalRecord.from_dict(
        {
            "event_id": "tool-call-2",
            "action": "send_email",
            "actor": "assistant_agent",
            "parent_event_id": "missing-approval",
            "metadata": {"risk": "external side effect"},
        }
    ),
]

report = AuditEngine().run(records)
print(report.to_dict())
```

Expected idea:

```text
The first tool call has a valid parent approval.
The second tool call succeeded operationally but references a missing parent cause.
CML reports broken causal lineage.
```

## Success criteria for outreach

- Maintainer says whether this belongs in Issues, Discussions, docs, or external example repo.
- If accepted, prepare a tiny PR with one example doc and no core dependency changes.
- If rejected, extract feedback and target another framework.
