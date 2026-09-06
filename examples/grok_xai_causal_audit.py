"""Grok/xAI-style LLM tool-use causal audit demo using CML.

This example is intentionally SDK-independent. It simulates the shape of a
modern tool-calling agent loop (web search, sandbox code execution, file write,
and an external API call) and maps every tool call into a CML ``CausalRecord``.

No network request, code execution, file mutation, or external API call is
actually performed by this demo.

Run from the repository root after installing the package:

    pip install -e .
    python examples/grok_xai_causal_audit.py

The invalid case demonstrates:

- ``CML-AUDIT-R1-MISSING_PARENT``
- ``CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL``
- experimental Cause Band drift findings

The valid case demonstrates the same workflow with explicit human approval and
an in-band intent trajectory.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cml.audit import AuditConfig, AuditEngine, AuditResult
from cml.ctag import CLASS, DOM, compute_ctag
from cml.experimental.cause_band import evaluate_fixture
from cml.record import Actor, CausalRecord


LLM_AGENT_RULES = """
include_context: true

custom_rules:
  - id: R8_DATA_EGRESS_REQUIRES_HUMAN_APPROVAL
    description: "High-risk external data egress must have a human approval ancestor."
    trigger_class: DATA_EGRESS
    severity: FAIL
    code: CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL
    require_ancestor_class: OVERRIDE
    require_ancestor_permitted_by_prefix: "human_approval:"
"""


INVALID_CAUSE_BAND = {
    "case_id": "grok-style-agent-intent-drift",
    "status": "experimental",
    "cause_band_policy": {"duration_threshold": "2_steps"},
    "trajectory": [
        {"step": 1, "band": "safe_range", "intent": "answer the user's research request"},
        {"step": 2, "band": "safe_range", "intent": "collect public evidence"},
        {"step": 3, "band": "warning_range", "intent": "run a sandbox calculation"},
        {"step": 4, "band": "danger_range", "intent": "prepare an external payload"},
        {"step": 5, "band": "critical_range", "intent": "send externally without approval"},
    ],
}


VALID_CAUSE_BAND = {
    "case_id": "grok-style-agent-in-band",
    "status": "experimental",
    "cause_band_policy": {"duration_threshold": "2_steps"},
    "trajectory": [
        {"step": 1, "band": "safe_range", "intent": "answer the user's research request"},
        {"step": 2, "band": "safe_range", "intent": "collect public evidence"},
        {"step": 3, "band": "safe_range", "intent": "run an approved sandbox calculation"},
        {"step": 4, "band": "safe_range", "intent": "write the requested local report"},
        {"step": 5, "band": "safe_range", "intent": "send only after explicit approval"},
    ],
}


def ctag(dom: int, cls: int, parent: str | None = None) -> int:
    """Compute a compact CTAG for the synthetic trace."""

    return compute_ctag(dom=dom, cls=cls, gen=0, parent_cause_id=parent)


def _sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def evidence_bundle(
    *,
    request: dict[str, Any],
    result: dict[str, Any],
    artifacts: list[str] | None = None,
) -> dict[str, Any]:
    """Create a small deterministic evidence bundle for a simulated tool call."""

    return {
        "request_digest": _sha256(request),
        "result_digest": _sha256(result),
        "artifacts": artifacts or [],
        "simulated": True,
    }


def tool_object(
    *,
    tool: str,
    intent_description: str,
    risk_level: str,
    approval_required: bool,
    approval_status: str,
    request: dict[str, Any],
    result: dict[str, Any],
    artifacts: list[str] | None = None,
) -> dict[str, Any]:
    """Return the LLM-native metadata stored inside ``CausalRecord.object``.

    vCML v0 keeps the stable top-level record schema intentionally small, so
    agent-specific fields live in the JSON-compatible ``object`` payload.
    """

    return {
        "tool": tool,
        "intent_description": intent_description,
        "risk_level": risk_level,
        "human_approval": {
            "required": approval_required,
            "status": approval_status,
        },
        "request": request,
        "result": result,
        "evidence_bundle": evidence_bundle(
            request=request,
            result=result,
            artifacts=artifacts,
        ),
    }


def make_invalid_trace() -> list[CausalRecord]:
    """Build a tool-use trace with a missing approval parent and intent drift."""

    human = Actor(pid=100, uid=1000, comm="human_operator")
    agent = Actor(pid=200, uid=1000, ppid=100, comm="grok_style_agent")
    sandbox = Actor(pid=300, uid=1000, ppid=200, comm="sandbox_tool")

    root = CausalRecord(
        id="request-1",
        timestamp=1,
        actor=human,
        action="approve_task",
        object={
            "intent_description": "Research public agent-audit patterns and save a local summary.",
            "risk_level": "low",
            "human_approval": {"required": False, "status": "root_request"},
            "evidence_bundle": {
                "request_digest": _sha256({"request": "research and save locally"}),
                "simulated": True,
            },
        },
        permitted_by="root_event:user_requested_research",
        parent_cause=None,
        ctag=ctag(DOM.USER, CLASS.OVERRIDE),
    )

    web_search = CausalRecord(
        id="tool-web-search-1",
        timestamp=2,
        actor=agent,
        action="read",
        object=tool_object(
            tool="web_search",
            intent_description="Collect public evidence relevant to the requested report.",
            risk_level="low",
            approval_required=False,
            approval_status="not_required",
            request={"query": "LLM agent causal audit patterns"},
            result={"documents_found": 4, "citations_recorded": True},
        ),
        permitted_by="task:public_research",
        parent_cause="request-1",
        ctag=ctag(DOM.AGENT, CLASS.READ, "request-1"),
    )

    code_execution = CausalRecord(
        id="tool-code-exec-1",
        timestamp=3,
        actor=sandbox,
        action="exec",
        object=tool_object(
            tool="code_execution",
            intent_description="Calculate a small summary metric in an isolated sandbox.",
            risk_level="medium",
            approval_required=False,
            approval_status="sandbox_policy",
            request={"language": "python", "operation": "count findings by category"},
            result={"exit_code": 0, "finding_count": 3},
            artifacts=["sandbox://finding-count.json"],
        ),
        permitted_by="policy:sandbox_read_only_calculation",
        parent_cause="tool-web-search-1",
        ctag=ctag(DOM.SANDBOX, CLASS.EXEC, "tool-web-search-1"),
    )

    file_write = CausalRecord(
        id="tool-file-write-1",
        timestamp=4,
        actor=agent,
        action="write",
        object=tool_object(
            tool="file_write",
            intent_description="Write the requested report to a local workspace file.",
            risk_level="low",
            approval_required=False,
            approval_status="within_user_scope",
            request={"path": "workspace/agent-audit-summary.md"},
            result={"bytes_written": 1240, "status": "simulated"},
            artifacts=["workspace/agent-audit-summary.md"],
        ),
        permitted_by="task:write_local_report",
        parent_cause="tool-code-exec-1",
        ctag=ctag(DOM.AGENT, CLASS.WRITE, "tool-code-exec-1"),
    )

    external_api = CausalRecord(
        id="tool-external-api-1",
        timestamp=5,
        actor=agent,
        action="send",
        object=tool_object(
            tool="external_api_call",
            intent_description="Send the report to an external endpoint not present in the root request.",
            risk_level="high",
            approval_required=True,
            approval_status="missing",
            request={"endpoint": "https://example.invalid/reports", "method": "POST"},
            result={"status": "simulated_not_executed"},
            artifacts=["workspace/agent-audit-summary.md"],
        ),
        permitted_by="human_approval:missing",
        parent_cause="missing-human-approval",
        ctag=ctag(DOM.THIRD_PARTY, CLASS.DATA_EGRESS, "missing-human-approval"),
    )

    return [root, web_search, code_execution, file_write, external_api]


def make_valid_trace() -> list[CausalRecord]:
    """Build the same workflow with explicit approval before external egress."""

    records = make_invalid_trace()[:-1]
    human = Actor(pid=100, uid=1000, comm="human_operator")
    agent = Actor(pid=200, uid=1000, ppid=100, comm="grok_style_agent")

    approval = CausalRecord(
        id="human-approval-external-send-1",
        timestamp=5,
        actor=human,
        action="approve_external_send",
        object={
            "intent_description": "Approve sending the prepared report to the named endpoint.",
            "risk_level": "high",
            "human_approval": {
                "required": True,
                "status": "approved",
                "approval_id": "ticket-LLM-42",
            },
            "evidence_bundle": {
                "approval_digest": _sha256({"approval_id": "ticket-LLM-42"}),
                "simulated": True,
            },
        },
        permitted_by="human_approval:ticket-LLM-42",
        parent_cause="tool-file-write-1",
        ctag=ctag(DOM.USER, CLASS.OVERRIDE, "tool-file-write-1"),
    )

    external_api = CausalRecord(
        id="tool-external-api-1",
        timestamp=6,
        actor=agent,
        action="send",
        object=tool_object(
            tool="external_api_call",
            intent_description="Send the approved report to the explicitly named endpoint.",
            risk_level="high",
            approval_required=True,
            approval_status="approved:ticket-LLM-42",
            request={"endpoint": "https://example.invalid/reports", "method": "POST"},
            result={"status": "simulated_success", "http_status": 202},
            artifacts=["workspace/agent-audit-summary.md"],
        ),
        permitted_by="human_approval:ticket-LLM-42",
        parent_cause="human-approval-external-send-1",
        ctag=ctag(DOM.THIRD_PARTY, CLASS.DATA_EGRESS, "human-approval-external-send-1"),
    )

    return [*records, approval, external_api]


def audit_trace(records: list[CausalRecord]) -> AuditResult:
    config = AuditConfig.from_yaml_string(LLM_AGENT_RULES)
    return AuditEngine(config).run(records)


def _record_label(record: CausalRecord) -> str:
    obj = record.object if isinstance(record.object, dict) else {}
    tool = obj.get("tool", record.action)
    risk = obj.get("risk_level", "n/a")
    return f"{record.id} [{tool}, risk={risk}]"


def render_report(
    name: str,
    records: list[CausalRecord],
    result: AuditResult,
    cause_band_result: dict[str, Any],
) -> str:
    violations = [finding for finding in result.findings if finding.severity == "FAIL"]
    warnings = [finding for finding in result.findings if finding.severity == "WARN"]
    band_codes = cause_band_result["predicted_codes"]
    passed = result.passed() and not band_codes

    lines = [
        "",
        "=" * 76,
        name,
        "=" * 76,
        f"DECISION: {'VALID CAUSAL CHAIN' if passed else 'REVIEW REQUIRED'}",
        "",
        "Causal chain:",
    ]

    for record in records:
        parent = record.parent_cause or "<root>"
        lines.append(f"  - {_record_label(record)} <- {parent}")

    lines.extend(["", "Core CML audit:"])
    if not result.findings:
        lines.append("  [OK] No core audit findings.")
    else:
        for finding in result.findings:
            marker = "VIOLATION" if finding.severity == "FAIL" else "WARNING"
            lines.append(f"  [{marker}] {finding.code} on {finding.record_id}")
            lines.append(f"            {finding.message}")

    lines.extend(["", "Cause Band tracking (experimental):"])
    lines.append(f"  bands: {' -> '.join(cause_band_result['bands'])}")
    lines.append(f"  direction: {cause_band_result['trajectory_direction']}")
    if band_codes:
        for code in band_codes:
            lines.append(f"  [WARNING] {code}")
    else:
        lines.append("  [OK] Intent remained inside the configured safe range.")

    lines.extend(
        [
            "",
            "Summary:",
            f"  records={result.total}",
            f"  core_warnings={len(warnings)}",
            f"  core_violations={len(violations)}",
            f"  cause_band_findings={len(band_codes)}",
        ]
    )
    return "\n".join(lines)


def run_case(
    name: str,
    records: list[CausalRecord],
    cause_band: dict[str, Any],
) -> tuple[AuditResult, dict[str, Any]]:
    result = audit_trace(records)
    cause_band_result = evaluate_fixture(cause_band)
    print(render_report(name, records, result, cause_band_result))
    return result, cause_band_result


def main() -> None:
    run_case("Invalid Grok/xAI-style tool-use trace", make_invalid_trace(), INVALID_CAUSE_BAND)
    run_case("Valid Grok/xAI-style tool-use trace", make_valid_trace(), VALID_CAUSE_BAND)


if __name__ == "__main__":
    main()
