"""Agent approval-lineage audit demo using CML.

This example uses a synthetic high-trust automation trace. It models action
records and approval lineage only; it does not include external targets,
offensive instructions, or runnable high-risk behavior.

Run after installing the package:

    pip install causal-memory-layer
    python examples/agent_approval_lineage_audit.py

Expected invalid findings:

    CML-AUDIT-R7-ML_ACTION_REQUIRES_POLICY_APPROVAL
    CML-AUDIT-R5-EXEC_REQUIRES_HUMAN_APPROVAL

The sensitive actions may look operationally valid in the sample trace, but
CML asks whether artifact preparation and sandbox execution were causally
permitted by policy/human approval records.
"""

from __future__ import annotations

import json

from cml.audit import AuditConfig, AuditEngine
from cml.ctag import CLASS, DOM, compute_ctag
from cml.record import Actor, CausalRecord


APPROVAL_LINEAGE_RULES = """
include_context: true

custom_rules:
  - id: R5_EXEC_REQUIRES_HUMAN_APPROVAL
    description: "Sandbox execution must have a valid human approval ancestor."
    trigger_class: EXEC
    severity: FAIL
    code: CML-AUDIT-R5-EXEC_REQUIRES_HUMAN_APPROVAL
    require_ancestor_class: OVERRIDE
    require_ancestor_permitted_by_prefix: "human_approval:"

  - id: R7_ML_ACTION_REQUIRES_POLICY_APPROVAL
    description: "High-risk ML action must have a valid policy approval ancestor."
    trigger_class: ML_ACTION
    severity: FAIL
    code: CML-AUDIT-R7-ML_ACTION_REQUIRES_POLICY_APPROVAL
    require_ancestor_class: OVERRIDE
    require_ancestor_permitted_by_prefix: "policy_approval:"
"""


def ctag(dom: int, cls: int, parent: str | None = None) -> int:
    """Compute a compact CTAG for this synthetic demo trace."""

    return compute_ctag(dom=dom, cls=cls, gen=0, parent_cause_id=parent)


def make_invalid_trace() -> list[CausalRecord]:
    """Build a trace where sensitive actions lack approval ancestors.

    The trace is structurally connected, so ordinary parent-reference checks
    pass. The custom rules fail because artifact preparation and sandbox
    execution do not descend from explicit policy/human approval records.
    """

    human = Actor(pid=100, uid=1000, comm="human_operator")
    agent = Actor(pid=200, uid=1000, ppid=100, comm="analysis_agent")
    sandbox = Actor(pid=300, uid=1000, ppid=200, comm="sandbox_runner")

    root = CausalRecord(
        id="task-1",
        timestamp=1,
        actor=human,
        action="approve_task",
        object={"task": "review patch and summarize risk", "scope": "read-only"},
        permitted_by="root_event:human_requested_patch_review",
        parent_cause=None,
        ctag=ctag(DOM.USER, CLASS.OVERRIDE),
    )

    read_patch = CausalRecord(
        id="read-patch-1",
        timestamp=2,
        actor=agent,
        action="read",
        object={"artifact": "patch.diff"},
        permitted_by="task:patch_review",
        parent_cause="task-1",
        ctag=ctag(DOM.AGENT, CLASS.READ, "task-1"),
    )

    write_analysis = CausalRecord(
        id="analysis-1",
        timestamp=3,
        actor=agent,
        action="write",
        object={"artifact": "risk_analysis.md"},
        permitted_by="task:write_risk_summary",
        parent_cause="read-patch-1",
        ctag=ctag(DOM.AGENT, CLASS.WRITE, "read-patch-1"),
    )

    prepare_artifact = CausalRecord(
        id="prepare-artifact-1",
        timestamp=4,
        actor=agent,
        action="prepare_high_risk_artifact",
        object={"artifact": "synthetic_test_artifact.py", "risk": "high", "synthetic": True},
        permitted_by="task:agent_prepared_artifact",
        parent_cause="analysis-1",
        ctag=ctag(DOM.AGENT, CLASS.ML_ACTION, "analysis-1"),
    )

    sandbox_exec = CausalRecord(
        id="sandbox-exec-1",
        timestamp=5,
        actor=sandbox,
        action="exec",
        object={"cmd": "python synthetic_test_artifact.py", "environment": "sandbox", "synthetic": True},
        permitted_by="task:sandbox_test",
        parent_cause="prepare-artifact-1",
        ctag=ctag(DOM.SANDBOX, CLASS.EXEC, "prepare-artifact-1"),
    )

    return [root, read_patch, write_analysis, prepare_artifact, sandbox_exec]


def make_valid_trace() -> list[CausalRecord]:
    """Build the same workflow with explicit policy and human approvals."""

    human = Actor(pid=100, uid=1000, comm="human_operator")
    agent = Actor(pid=200, uid=1000, ppid=100, comm="analysis_agent")
    sandbox = Actor(pid=300, uid=1000, ppid=200, comm="sandbox_runner")

    root = CausalRecord(
        id="task-1",
        timestamp=1,
        actor=human,
        action="approve_task",
        object={"task": "review patch and summarize risk", "scope": "read-only"},
        permitted_by="root_event:human_requested_patch_review",
        parent_cause=None,
        ctag=ctag(DOM.USER, CLASS.OVERRIDE),
    )

    read_patch = CausalRecord(
        id="read-patch-1",
        timestamp=2,
        actor=agent,
        action="read",
        object={"artifact": "patch.diff"},
        permitted_by="task:patch_review",
        parent_cause="task-1",
        ctag=ctag(DOM.AGENT, CLASS.READ, "task-1"),
    )

    write_analysis = CausalRecord(
        id="analysis-1",
        timestamp=3,
        actor=agent,
        action="write",
        object={"artifact": "risk_analysis.md"},
        permitted_by="task:write_risk_summary",
        parent_cause="read-patch-1",
        ctag=ctag(DOM.AGENT, CLASS.WRITE, "read-patch-1"),
    )

    policy_approval = CausalRecord(
        id="policy-approval-1",
        timestamp=4,
        actor=human,
        action="approve_policy",
        object={"approval": "allow synthetic high-risk artifact preparation for lab review"},
        permitted_by="policy_approval:defensive_lab_review",
        parent_cause="analysis-1",
        ctag=ctag(DOM.USER, CLASS.OVERRIDE, "analysis-1"),
    )

    prepare_artifact = CausalRecord(
        id="prepare-artifact-1",
        timestamp=5,
        actor=agent,
        action="prepare_high_risk_artifact",
        object={"artifact": "synthetic_test_artifact.py", "risk": "high", "synthetic": True},
        permitted_by="policy_approval:defensive_lab_review",
        parent_cause="policy-approval-1",
        ctag=ctag(DOM.AGENT, CLASS.ML_ACTION, "policy-approval-1"),
    )

    human_exec_approval = CausalRecord(
        id="human-approval-exec-1",
        timestamp=6,
        actor=human,
        action="approve_sandbox_exec",
        object={"approval": "allow synthetic artifact execution only in sandbox"},
        permitted_by="human_approval:ticket-123",
        parent_cause="prepare-artifact-1",
        ctag=ctag(DOM.USER, CLASS.OVERRIDE, "prepare-artifact-1"),
    )

    sandbox_exec = CausalRecord(
        id="sandbox-exec-1",
        timestamp=7,
        actor=sandbox,
        action="exec",
        object={"cmd": "python synthetic_test_artifact.py", "environment": "sandbox", "synthetic": True},
        permitted_by="human_approval:ticket-123",
        parent_cause="human-approval-exec-1",
        ctag=ctag(DOM.SANDBOX, CLASS.EXEC, "human-approval-exec-1"),
    )

    return [
        root,
        read_patch,
        write_analysis,
        policy_approval,
        prepare_artifact,
        human_exec_approval,
        sandbox_exec,
    ]


def run_case(name: str, records: list[CausalRecord]) -> None:
    config = AuditConfig.from_yaml_string(APPROVAL_LINEAGE_RULES)
    result = AuditEngine(config).run(records)

    print(f"\n=== {name} ===")
    print(json.dumps(result.to_dict(), indent=2))

    if result.passed():
        print("PASS: high-risk actions have valid causal approval lineage.")
    else:
        print("FAIL: one or more high-risk actions lack valid causal approval lineage.")


def main() -> None:
    run_case("Invalid approval-lineage trace", make_invalid_trace())
    run_case("Valid approval-lineage trace", make_valid_trace())


if __name__ == "__main__":
    main()
