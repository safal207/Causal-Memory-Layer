"""Bounded adapter tests; no tools are executed and no network is used."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from cml.ctag import CLASS, DOM, compute_ctag
from cml.integrations.otel_genai import SpanBinding, audit_span, observe_span
from cml.record import Actor, CausalRecord


def span(status="OK", call="call-1", trace=1, sid=2, **attrs):
    values = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "synthetic_exec",
        "gen_ai.tool.call.id": call,
        **attrs,
    }
    return SimpleNamespace(
        attributes=values,
        context=SimpleNamespace(trace_id=trace, span_id=sid),
        status=SimpleNamespace(status_code=SimpleNamespace(name=status)),
        end_time=4,
        parent=SimpleNamespace(span_id=9),
    )


def record(id_, parent, timestamp, action, permission, cls, pid):
    return CausalRecord(
        id=id_, parent_cause=parent, timestamp=timestamp,
        actor=Actor(pid=pid, uid=1000), action=action, object={},
        permitted_by=permission,
        ctag=compute_ctag(DOM.AGENT if action == "exec" else DOM.USER,
                          cls, 0, parent),
    )


def records():
    return [
        record("task", None, 1, "task", "root_event:task", CLASS.OVERRIDE, 1),
        record("approval", "task", 2, "approve", "human_approval:demo", CLASS.OVERRIDE, 1),
        record("execution", "approval", 3, "exec", "task:demo", CLASS.EXEC, 2),
    ]


def binding():
    return SpanBinding(1, 2, "synthetic_exec", "call-1", "execution")


@pytest.mark.parametrize("status", ["OK", "UNSET", "ERROR"])
def test_status_is_not_authority(status):
    r = audit_span(span(status=status), binding(), records())
    assert r.lineage == "LINEAGE_SUPPORTED"
    assert r.observation.status == status


def test_success_without_approval():
    root, _, execution = records()
    execution = replace(execution, parent_cause="task",
                        ctag=compute_ctag(DOM.AGENT, CLASS.EXEC, 0, "task"))
    r = audit_span(span(), binding(), [root, execution])
    assert r.lineage == "LINEAGE_NOT_SUPPORTED"
    assert "CML-AUDIT-OTEL-DEMO-EXEC-APPROVAL" in r.finding_codes


def test_missing_parent_is_native_cml_finding():
    root, _, execution = records()
    r = audit_span(span(), binding(), [root, execution])
    assert r.lineage == "LINEAGE_NOT_SUPPORTED"
    assert "CML-AUDIT-R1-MISSING_PARENT" in r.finding_codes


def test_forged_telemetry_authority_is_ignored():
    s = span(**{"cml.permitted_by": "human_approval:forged",
                "gen_ai.tool.call.arguments": "secret-payload"})
    r = audit_span(s, None, records())
    assert r.lineage == "INDETERMINATE"
    assert "secret-payload" not in repr(r)
    assert "forged" not in repr(r)


@pytest.mark.parametrize("change", [
    {"trace_id": 4}, {"span_id": 5}, {"tool_name": "other"}, {"call_id": "other"},
])
def test_cross_context_binding_mismatch(change):
    r = audit_span(span(), replace(binding(), **change), records())
    assert r.lineage == "INDETERMINATE"
    assert r.reason == "binding_mismatch"


def test_missing_call_id_not_synthesized():
    r = audit_span(span(call=None), binding(), records())
    assert r.lineage == "INDETERMINATE"
    assert r.observation.call_id is None


def test_missing_bound_record():
    assert audit_span(span(), binding(), records()[:2]).reason == "missing_bound_record"


def test_duplicate_records_do_not_overwrite():
    rs = records()
    assert audit_span(span(), binding(), rs + [rs[-1]]).reason == "ambiguous_record_identity"


def test_cycle_is_not_supported():
    rs = records()
    rs[1] = replace(rs[1], parent_cause="execution", timestamp=3)
    assert audit_span(span(), binding(), rs).reason == "causal_cycle"


def test_parent_after_child_is_not_supported():
    rs = records()
    rs[1] = replace(rs[1], timestamp=4)
    assert audit_span(span(), binding(), rs).reason == "parent_after_child"


def test_unsupported_action():
    rs = records()
    rs[-1] = replace(rs[-1], action="read")
    assert audit_span(span(), binding(), rs).reason == "unsupported_record_action"


@pytest.mark.parametrize("s", [
    span(trace=0), span(sid=0), span(trace=True), span(call=123),
    span(**{"gen_ai.operation.name": "chat"}),
    span(**{"gen_ai.tool.name": ""}),
])
def test_invalid_span(s):
    with pytest.raises(ValueError):
        observe_span(s)


def test_unfinished_span():
    s = span()
    s.end_time = None
    with pytest.raises(ValueError, match="unfinished"):
        observe_span(s)


def test_unrelated_approval_does_not_supply_ancestry():
    root, approval, execution = records()
    execution = replace(execution, parent_cause="task",
                        ctag=compute_ctag(DOM.AGENT, CLASS.EXEC, 0, "task"))
    assert audit_span(span(), binding(), [root, approval, execution]).lineage == "LINEAGE_NOT_SUPPORTED"


def test_actual_sdk_in_memory_export_if_installed():
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    try:
        with provider.get_tracer("cml.otel.demo").start_as_current_span(
            "execute_tool synthetic_exec", attributes={
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "synthetic_exec",
                "gen_ai.tool.call.id": "call-1",
            }
        ):
            pass
        actual, = exporter.get_finished_spans()
        ctx = actual.context
        bound = replace(binding(), trace_id=ctx.trace_id, span_id=ctx.span_id)
        assert audit_span(actual, bound, records()).lineage == "LINEAGE_SUPPORTED"
        assert audit_span(actual, None, records()).lineage == "INDETERMINATE"
    finally:
        provider.shutdown()
