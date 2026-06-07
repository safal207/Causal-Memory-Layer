"""CrewAI-style causal audit demo using CML.

This example does not import CrewAI directly. It shows how a typical
agent/task/tool workflow trace can be mapped into CML records and audited
for broken causal lineage.

Run after installing the package:

    pip install causal-memory-layer
    python examples/crewai_style_causal_audit.py

Expected result:

    CML-AUDIT-R1-MISSING_PARENT

The final tool call succeeds operationally in the sample trace, but its
parent cause points to a missing approval/task record. CML flags that as
causally invalid.
"""

from __future__ import annotations

import json

from cml.audit import AuditEngine
from cml.record import Actor, CausalRecord


def make_crewai_style_trace() -> list[CausalRecord]:
    """Build a small CrewAI-style action trace.

    The trace contains:

    1. A root human-approved research goal.
    2. A valid researcher-agent search action linked to the approval.
    3. A valid analyst-agent write action linked to the search result.
    4. An invalid assistant-agent external send action pointing to a missing
       approval/task parent.
    """

    operator = Actor(pid=100, uid=1000, comm="human_operator")
    researcher_agent = Actor(pid=101, uid=1000, ppid=100, comm="researcher_agent")
    analyst_agent = Actor(pid=102, uid=1000, ppid=100, comm="analyst_agent")
    assistant_agent = Actor(pid=103, uid=1000, ppid=100, comm="assistant_agent")

    approval = CausalRecord(
        id="approval-1",
        timestamp=1,
        actor=operator,
        action="approve_task",
        object={
            "task": "research open-source agent audit patterns",
            "risk": "low",
        },
        permitted_by="root_event:human_approved_research_goal",
        parent_cause=None,
    )

    search_tool_call = CausalRecord(
        id="tool-call-search-1",
        timestamp=2,
        actor=researcher_agent,
        action="search",
        object={
            "tool": "web_search",
            "query": "agent workflow auditability patterns",
        },
        permitted_by="task:researcher_agent_search",
        parent_cause="approval-1",
    )

    summary_write = CausalRecord(
        id="task-write-summary-1",
        timestamp=3,
        actor=analyst_agent,
        action="write",
        object={
            "artifact": "summary.md",
            "description": "summarize search findings",
        },
        permitted_by="task:analyst_agent_summary",
        parent_cause="tool-call-search-1",
    )

    external_send = CausalRecord(
        id="tool-call-send-1",
        timestamp=4,
        actor=assistant_agent,
        action="send",
        object={
            "tool": "email",
            "recipient": "external@example.com",
            "description": "send summary to external recipient",
        },
        permitted_by="task:assistant_agent_external_send",
        parent_cause="missing-human-approval",
    )

    return [approval, search_tool_call, summary_write, external_send]


def main() -> None:
    records = make_crewai_style_trace()
    result = AuditEngine().run(records)

    print("CML audit result for CrewAI-style trace")
    print(json.dumps(result.to_dict(), indent=2))

    if not result.passed():
        print("\nFinding summary:")
        for finding in result.findings:
            print(f"- {finding.code}: {finding.message}")


if __name__ == "__main__":
    main()
