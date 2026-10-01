"""Offline demo: can an export trace support its claimed approval lineage?

Run after installing CML: python examples/structural_audit_demo.py
All data is synthetic. Nothing is exported, approved, or blocked by this demo.
"""

from dataclasses import replace
import json

from cml.audit import AuditConfig, AuditEngine, CustomRule
from cml.ctag import CLASS
from cml.record import Actor, CausalRecord


def run_demo() -> dict:
    root = CausalRecord(
        id="request", timestamp=1, actor=Actor(pid=1, uid=1), action="exec",
        object="synthetic-report", permitted_by="root_event:user_request",
    )
    approval = replace(
        root, id="approval", timestamp=2, parent_cause="request",
        permitted_by="approval:reviewed",
    )
    export = replace(
        root, id="export", timestamp=3, action="send", parent_cause="approval",
        permitted_by="network:send",
    )
    engine = AuditEngine(AuditConfig(custom_rules=[CustomRule(
        id="EXPORT-APPROVAL", description="Export must descend from recorded approval",
        trigger_class=CLASS.NET_OUT,
        require_ancestor_permitted_by_prefix="approval:",
        code="DEMO-EXPORT-MISSING-APPROVAL",
    )]))
    cases = {
        "valid_approval_lineage": [root, approval, export],
        "approval_bypassed": [root, approval, replace(export, parent_cause="request")],
        "duplicate_approval_identity": [
            root, replace(approval, permitted_by="request:unreviewed"), approval, export,
        ],
        "circular_approval_lineage": [root, replace(approval, parent_cause="export"), export],
    }
    outcomes = {}
    for name, records in cases.items():
        try:
            result = engine.run(records)
        except ValueError as exc:
            outcomes[name] = {"status": "INVALID_INPUT", "reason": str(exc)}
        else:
            outcomes[name] = {
                "status": "PASS" if result.passed() else "FAIL",
                "findings": [f.code for f in result.findings],
            }
    return outcomes


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2))
