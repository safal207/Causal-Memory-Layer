"""Experimental read-only GenAI span / CML lineage correlation.

Telemetry is observation, never an authority source. See the integration guide.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from cml.audit import AuditConfig, AuditEngine, CustomRule, Severity
from cml.ctag import CLASS
from cml.record import CausalRecord, records_to_index


@dataclass(frozen=True)
class ToolObservation:
    trace_id: int
    span_id: int
    tool_name: str
    call_id: Optional[str]
    status: str


@dataclass(frozen=True)
class SpanBinding:
    """Supplied by a trusted host, never reconstructed from span attributes."""

    trace_id: int
    span_id: int
    tool_name: str
    call_id: str
    record_id: str


@dataclass(frozen=True)
class LineageResult:
    observation: ToolObservation
    lineage: str
    reason: str
    finding_codes: tuple[str, ...] = ()


def _valid_id(value: object, bits: int) -> bool:
    return type(value) is int and 0 < value < (1 << bits)


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def observe_span(span: object) -> ToolObservation:
    """Read a finished SDK ReadableSpan or object with the same fields.

    The deliberately small profile accepts execute_tool only. No arguments,
    results, messages, baggage, links or custom authority fields are copied.
    """
    attrs = span.attributes or {}
    if attrs.get("gen_ai.operation.name") != "execute_tool":
        raise ValueError("not an execute_tool span")
    if span.end_time is None:
        raise ValueError("unfinished span")
    ctx = span.context
    if ctx is None or not _valid_id(ctx.trace_id, 128) or not _valid_id(ctx.span_id, 64):
        raise ValueError("invalid span context")
    name = attrs.get("gen_ai.tool.name")
    call = attrs.get("gen_ai.tool.call.id")
    if not _nonempty(name) or (call is not None and not _nonempty(call)):
        raise ValueError("invalid tool identity")
    status = span.status.status_code.name
    if status not in {"OK", "ERROR", "UNSET"}:
        raise ValueError("invalid span status")
    return ToolObservation(ctx.trace_id, ctx.span_id, name, call, status)


def _lineage_config() -> AuditConfig:
    config = AuditConfig()
    rule = CustomRule(
        id="OTEL_DEMO_EXEC_APPROVAL",
        description="Synthetic exec record requires human approval ancestry",
        trigger_class=CLASS.EXEC,
        severity=Severity.FAIL,
        code="CML-AUDIT-OTEL-DEMO-EXEC-APPROVAL",
        require_ancestor_class=CLASS.OVERRIDE,
        require_ancestor_permitted_by_prefix="human_approval:",
    )
    config.custom_rules.append(rule)
    config.rules_enabled[rule.id] = True
    return config


def audit_span(
    span: object,
    binding: Optional[SpanBinding],
    records: Iterable[CausalRecord],
) -> LineageResult:
    """Audit one observed tool against separately supplied trusted records.

    LINEAGE_SUPPORTED is conditional on the host inputs and configured rules;
    it is NOT an authorization verdict, a dispatch instruction or effect proof.
    """
    obs = observe_span(span)

    def result(state: str, reason: str, codes: tuple[str, ...] = ()) -> LineageResult:
        return LineageResult(obs, state, reason, codes)

    if binding is None or obs.call_id is None:
        return result("INDETERMINATE", "missing_binding_or_call_id")
    if (
        not _valid_id(binding.trace_id, 128)
        or not _valid_id(binding.span_id, 64)
        or not all(_nonempty(x) for x in (binding.tool_name, binding.call_id, binding.record_id))
    ):
        return result("INDETERMINATE", "invalid_binding")
    if (obs.trace_id, obs.span_id, obs.tool_name, obs.call_id) != (
        binding.trace_id, binding.span_id, binding.tool_name, binding.call_id
    ):
        return result("INDETERMINATE", "binding_mismatch")

    try:
        index = records_to_index(list(records))
    except ValueError:
        return result("INDETERMINATE", "ambiguous_record_identity")
    target = index.get(binding.record_id)
    if target is None:
        return result("INDETERMINATE", "missing_bound_record")
    if target.action != "exec" or (
        target.ctag is not None and ((target.ctag >> 8) & 0xF) != CLASS.EXEC
    ):
        return result("INDETERMINATE", "unsupported_record_action")

    # Traverse only the target's declared ancestry, not unrelated workflows.
    chain: list[CausalRecord] = []
    seen: set[str] = set()
    current = target
    while True:
        if current.id in seen:
            return result("LINEAGE_NOT_SUPPORTED", "causal_cycle")
        seen.add(current.id)
        chain.append(current)
        if current.parent_cause is None:
            break
        parent = index.get(current.parent_cause)
        if parent is None:
            # Let CML emit its native missing-parent finding.
            break
        if type(parent.timestamp) is not int or type(current.timestamp) is not int:
            return result("INDETERMINATE", "invalid_record_time")
        if parent.timestamp > current.timestamp:
            return result("LINEAGE_NOT_SUPPORTED", "parent_after_child")
        current = parent

    chain.reverse()
    audit = AuditEngine(_lineage_config()).run(chain)
    codes = tuple(sorted({f.code for f in audit.findings if f.severity != Severity.OK}))
    if not audit.passed():
        return result("LINEAGE_NOT_SUPPORTED", "cml_audit_failed", codes)
    if not chain[0].is_root() or audit.warnings:
        return result("INDETERMINATE", "incomplete_or_warning_lineage", codes)
    return result("LINEAGE_SUPPORTED", "bounded_cml_lineage_check", codes)
