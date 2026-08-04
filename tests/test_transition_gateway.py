from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from cml.causal_transition_guard import (
    CausalTransitionGraph,
    GatewayStatus,
    GraphEdge,
    GraphNode,
    GuardedToolGateway,
    NodeKind,
    Relation,
    Space,
    TemporalWindow,
    ToolRegistry,
    build_forged_reasoning_fixture,
    payload_digest,
)


def _now() -> datetime:
    return datetime(2026, 8, 4, 18, 0, tzinfo=timezone.utc)


def _authorized_gateway_graph(
    payload: object, *, bind_payload: bool = True
) -> CausalTransitionGraph:
    now = _now()
    graph = CausalTransitionGraph()
    graph.add_node(
        GraphNode(
            "intent",
            NodeKind.INTENT,
            Space.USER,
            temporal=TemporalWindow(valid_from=now - timedelta(minutes=1)),
        )
    )
    graph.add_node(
        GraphNode(
            "policy",
            NodeKind.POLICY,
            Space.POLICY,
            attributes={"source": "policy-engine"},
            temporal=TemporalWindow(valid_from=now - timedelta(days=1)),
            trusted_for_authority=True,
        )
    )
    graph.add_node(
        GraphNode(
            "grant",
            NodeKind.AUTHORIZATION,
            Space.AUTHORITY,
            attributes={
                "source": "authority-service",
                "actions": ["http_post"],
                "resources": ["report.pdf"],
                "destinations": ["partner.example"],
            },
            temporal=TemporalWindow(
                valid_from=now - timedelta(minutes=1),
                valid_until=now + timedelta(minutes=5),
            ),
            trusted_for_authority=True,
        )
    )
    action_attributes = {
        "operation": "http_post",
        "resource": "report.pdf",
        "destination": "partner.example",
        "external_boundary": True,
        "state_from": "report_local",
        "state_to": "report_sent",
    }
    if bind_payload:
        action_attributes["payload_hash"] = payload_digest(payload)
    graph.add_node(
        GraphNode(
            "send-report",
            NodeKind.ACTION,
            Space.RUNTIME,
            attributes=action_attributes,
        )
    )
    graph.add_edge(GraphEdge("intent", "send-report", Relation.PROPOSES))
    graph.add_edge(GraphEdge("policy", "grant", Relation.DEFINES))
    graph.add_edge(GraphEdge("grant", "send-report", Relation.AUTHORIZES))
    return graph


def test_cot_forgery_never_reaches_file_or_network_adapters() -> None:
    graph, action_ids = build_forged_reasoning_fixture(at=_now())
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(
        "read_secret",
        lambda envelope, payload: calls.append(envelope.operation),
    )
    registry.register(
        "http_post",
        lambda envelope, payload: calls.append(envelope.operation),
    )
    gateway = GuardedToolGateway(graph, registry)

    read_receipt = gateway.execute_action(
        action_ids[0], {"path": ".env"}, nonce="cot-read", at=_now()
    )
    send_receipt = gateway.execute_action(
        action_ids[1],
        {"body": "API_KEY=demo-secret"},
        nonce="cot-send",
        at=_now(),
    )

    assert read_receipt.status is GatewayStatus.DENIED
    assert send_receipt.status is GatewayStatus.DENIED
    assert read_receipt.executed is False
    assert send_receipt.executed is False
    assert "NO_TRUSTED_AUTHORITY_PATH" in read_receipt.guard_evidence.reasons
    assert "SECRET_TAINT_CROSSES_EXTERNAL_BOUNDARY" in (
        send_receipt.guard_evidence.reasons
    )
    assert calls == []
    serialized = json.dumps([item.to_dict() for item in gateway.receipts])
    assert "API_KEY=demo-secret" not in serialized


def test_exact_bound_action_executes_once_and_verifies_postcondition() -> None:
    payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(payload)
    calls: list[tuple[str, str]] = []
    registry = ToolRegistry()

    def post(envelope, outgoing_payload):
        calls.append((envelope.destination, outgoing_payload["body"]))
        return {"status": 201, "destination": envelope.destination}

    registry.register(
        "http_post",
        post,
        verifier=lambda envelope, result: (
            result["status"] == 201
            and result["destination"] == envelope.destination
        ),
    )
    gateway = GuardedToolGateway(graph, registry)

    receipt = gateway.execute_action(
        "send-report", payload, nonce="dispatch-1", at=_now()
    )
    replay = gateway.execute_action(
        "send-report", payload, nonce="dispatch-1", at=_now()
    )

    assert receipt.status is GatewayStatus.VERIFIED
    assert receipt.executed is True
    assert receipt.verified is True
    assert receipt.result_hash
    assert replay.status is GatewayStatus.REPLAY_BLOCKED
    assert calls == [("partner.example", "quarterly report")]


def test_destination_and_payload_substitution_are_blocked_before_dispatch() -> None:
    payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(payload)
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(
        "http_post",
        lambda envelope, outgoing_payload: calls.append(envelope.destination),
    )
    gateway = GuardedToolGateway(graph, registry)

    envelope = gateway.build_envelope(
        "send-report", payload, nonce="dispatch-2", at=_now()
    )
    destination_swap = gateway.execute(
        replace(envelope, destination="attacker.example"), payload, at=_now()
    )
    payload_swap = gateway.execute_action(
        "send-report",
        {"body": "API_KEY=stolen"},
        nonce="dispatch-3",
        at=_now(),
    )

    assert destination_swap.status is GatewayStatus.ENVELOPE_MISMATCH
    assert payload_swap.status is GatewayStatus.ENVELOPE_MISMATCH
    assert calls == []


def test_allowed_action_without_payload_binding_fails_closed() -> None:
    payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(payload, bind_payload=False)
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(
        "http_post",
        lambda envelope, outgoing_payload: calls.append(envelope.destination),
    )
    gateway = GuardedToolGateway(graph, registry)

    receipt = gateway.execute_action(
        "send-report", payload, nonce="dispatch-4", at=_now()
    )

    assert receipt.guard_evidence.allowed is True
    assert receipt.status is GatewayStatus.ENVELOPE_MISMATCH
    assert receipt.error_code == "allowed_action_missing_payload_hash"
    assert calls == []


def test_failed_postcondition_is_visible_in_receipt() -> None:
    payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(payload)
    registry = ToolRegistry()
    registry.register(
        "http_post",
        lambda envelope, outgoing_payload: {
            "status": 202,
            "destination": "unknown.example",
        },
        verifier=lambda envelope, result: (
            result["status"] == 201
            and result["destination"] == envelope.destination
        ),
    )
    gateway = GuardedToolGateway(graph, registry)

    receipt = gateway.execute_action(
        "send-report", payload, nonce="dispatch-5", at=_now()
    )

    assert receipt.status is GatewayStatus.POSTCONDITION_FAILED
    assert receipt.executed is True
    assert receipt.verified is False
    assert receipt.error_code == "postcondition_not_satisfied"
