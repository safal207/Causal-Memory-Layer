from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Event, Lock, Thread

import pytest

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
from scripts.run_asb15_gateway_demo import gateway_demo_passes


_PAYLOAD_HASH_UNSET = object()


def _now() -> datetime:
    return datetime(2026, 8, 4, 18, 0, tzinfo=timezone.utc)


def _authorized_gateway_graph(
    payload: object,
    *,
    bind_payload: bool = True,
    payload_hash_override: object = _PAYLOAD_HASH_UNSET,
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
    action_attributes: dict[str, object] = {
        "operation": "http_post",
        "resource": "report.pdf",
        "destination": "partner.example",
        "external_boundary": True,
        "state_from": "report_local",
        "state_to": "report_sent",
    }
    if payload_hash_override is not _PAYLOAD_HASH_UNSET:
        action_attributes["payload_hash"] = payload_hash_override
    elif bind_payload:
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


def _fixed_gateway(
    graph: CausalTransitionGraph, registry: ToolRegistry
) -> GuardedToolGateway:
    return GuardedToolGateway(graph, registry, clock=_now)


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
    gateway = _fixed_gateway(graph, registry)

    read_receipt = gateway.execute_action(
        action_ids[0], {"path": ".env"}, nonce="cot-read"
    )
    send_receipt = gateway.execute_action(
        action_ids[1],
        {"body": "API_KEY=demo-secret"},
        nonce="cot-send",
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
    assert gateway_demo_passes((read_receipt, send_receipt), calls)

    generic_denial = replace(
        read_receipt,
        guard_evidence=replace(
            read_receipt.guard_evidence,
            reasons=("NO_ACTIVE_INTENT_PATH",),
        ),
    )
    assert not gateway_demo_passes((generic_denial, send_receipt), calls)


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
    gateway = _fixed_gateway(graph, registry)

    receipt = gateway.execute_action(
        "send-report", payload, nonce="dispatch-1"
    )
    replay = gateway.execute_action(
        "send-report", payload, nonce="dispatch-1"
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
    gateway = _fixed_gateway(graph, registry)

    envelope = gateway.build_envelope(
        "send-report", payload, nonce="dispatch-2"
    )
    destination_swap = gateway.execute(
        replace(envelope, destination="attacker.example"), payload
    )
    payload_swap = gateway.execute_action(
        "send-report",
        {"body": "API_KEY=stolen"},
        nonce="dispatch-3",
    )
    malformed_envelope = gateway.execute(
        replace(envelope, payload_hash="à" * 64), payload
    )

    assert destination_swap.status is GatewayStatus.ENVELOPE_MISMATCH
    assert payload_swap.status is GatewayStatus.ENVELOPE_MISMATCH
    assert malformed_envelope.status is GatewayStatus.ENVELOPE_MISMATCH
    assert malformed_envelope.error_code == "invalid_envelope_payload_hash"
    assert calls == []


@pytest.mark.parametrize(
    "malformed_hash",
    ["", "A" * 64, "g" * 64, "à" * 64, "0" * 63],
)
def test_malformed_graph_payload_hash_fails_closed_with_receipt(
    malformed_hash: str,
) -> None:
    payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(
        payload, payload_hash_override=malformed_hash
    )
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(
        "http_post",
        lambda envelope, outgoing_payload: calls.append(envelope.destination),
    )
    gateway = _fixed_gateway(graph, registry)

    receipt = gateway.execute_action(
        "send-report", payload, nonce="malformed-hash"
    )

    assert receipt.status is GatewayStatus.ENVELOPE_MISMATCH
    assert receipt.executed is False
    assert receipt.error_code == "invalid_graph_payload_hash"
    assert gateway.receipts == (receipt,)
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
    gateway = _fixed_gateway(graph, registry)

    receipt = gateway.execute_action(
        "send-report", payload, nonce="dispatch-4"
    )

    assert receipt.guard_evidence.allowed is True
    assert receipt.status is GatewayStatus.ENVELOPE_MISMATCH
    assert receipt.error_code == "allowed_action_missing_payload_hash"
    assert calls == []


def test_authorization_is_rechecked_using_gateway_dispatch_clock() -> None:
    payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(payload)
    current = [_now()]
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(
        "http_post",
        lambda envelope, outgoing_payload: calls.append(envelope.destination),
    )
    gateway = GuardedToolGateway(
        graph, registry, clock=lambda: current[0]
    )
    envelope = gateway.build_envelope(
        "send-report", payload, nonce="expires-at-dispatch"
    )

    current[0] = _now() + timedelta(minutes=6)
    receipt = gateway.execute(envelope, payload)

    assert receipt.status is GatewayStatus.DENIED
    assert receipt.executed is False
    assert "NO_TRUSTED_AUTHORITY_PATH" in receipt.guard_evidence.reasons
    assert calls == []


def test_failed_postcondition_is_visible_and_nonce_stays_reserved() -> None:
    payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(payload)
    calls: list[str] = []
    registry = ToolRegistry()

    def post(envelope, outgoing_payload):
        calls.append(envelope.destination)
        return {"status": 202, "destination": "unknown.example"}

    registry.register(
        "http_post",
        post,
        verifier=lambda envelope, result: (
            result["status"] == 201
            and result["destination"] == envelope.destination
        ),
    )
    gateway = _fixed_gateway(graph, registry)

    receipt = gateway.execute_action(
        "send-report", payload, nonce="dispatch-5"
    )
    replay = gateway.execute_action(
        "send-report", payload, nonce="dispatch-5"
    )

    assert receipt.status is GatewayStatus.POSTCONDITION_FAILED
    assert receipt.executed is True
    assert receipt.verified is False
    assert receipt.error_code == "postcondition_not_satisfied"
    assert replay.status is GatewayStatus.REPLAY_BLOCKED
    assert calls == ["partner.example"]


def test_completed_receipts_redact_payload_and_result_secrets() -> None:
    payload_secret = "PAYLOAD_SECRET_123"
    result_secret = "RESULT_SECRET_456"
    payload = {"body": payload_secret}
    graph = _authorized_gateway_graph(payload)

    def run(verified: bool, nonce: str):
        registry = ToolRegistry()
        registry.register(
            "http_post",
            lambda envelope, outgoing_payload: {
                "status": 201,
                "destination": envelope.destination,
                "credential": result_secret,
            },
            verifier=lambda envelope, result: verified,
        )
        gateway = _fixed_gateway(graph, registry)
        return gateway.execute_action("send-report", payload, nonce=nonce)

    verified_receipt = run(True, "redaction-verified")
    failed_receipt = run(False, "redaction-failed")
    serialized = json.dumps(
        [verified_receipt.to_dict(), failed_receipt.to_dict()]
    )

    assert verified_receipt.status is GatewayStatus.VERIFIED
    assert failed_receipt.status is GatewayStatus.POSTCONDITION_FAILED
    assert payload_secret not in serialized
    assert result_secret not in serialized
    assert verified_receipt.result_hash
    assert failed_receipt.result_hash


def test_payload_digest_preserves_sequence_and_scalar_types() -> None:
    assert payload_digest([1, True]) != payload_digest((1, True))
    assert payload_digest(1) != payload_digest(True)
    assert payload_digest(1) != payload_digest(1.0)
    assert payload_digest(b"abc") != payload_digest(
        {"type": "bytes", "value": "YWJj"}
    )


def test_uncanonicalizable_payload_returns_receipt_without_dispatch() -> None:
    allowed_payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(allowed_payload)
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(
        "http_post",
        lambda envelope, outgoing_payload: calls.append(envelope.destination),
    )
    gateway = _fixed_gateway(graph, registry)

    receipt = gateway.execute_action(
        "send-report", object(), nonce="dispatch-6"
    )

    assert receipt.status is GatewayStatus.ENVELOPE_MISMATCH
    assert receipt.executed is False
    assert receipt.error_code == "payload_not_canonicalizable"
    assert calls == []
    assert gateway.receipts == (receipt,)


def test_uncanonicalizable_result_still_emits_executed_receipt() -> None:
    payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(payload)
    registry = ToolRegistry()
    registry.register(
        "http_post",
        lambda envelope, outgoing_payload: object(),
    )
    gateway = _fixed_gateway(graph, registry)

    receipt = gateway.execute_action(
        "send-report", payload, nonce="dispatch-7"
    )

    assert receipt.status is GatewayStatus.EXECUTED_UNVERIFIED
    assert receipt.executed is True
    assert receipt.verified is False
    assert receipt.result_hash is None
    assert receipt.error_code == "result_not_canonicalizable"


def test_gateway_dispatches_snapshot_not_caller_owned_payload() -> None:
    payload = {"body": {"value": "quarterly report"}}
    graph = _authorized_gateway_graph(payload)
    dispatched_values: list[str] = []
    registry = ToolRegistry()

    def post(envelope, outgoing_payload):
        payload["body"]["value"] = "forged after validation"
        dispatched_values.append(outgoing_payload["body"]["value"])
        return {"status": 201, "destination": envelope.destination}

    registry.register(
        "http_post",
        post,
        verifier=lambda envelope, result: (
            result["status"] == 201
            and result["destination"] == envelope.destination
        ),
    )
    gateway = _fixed_gateway(graph, registry)

    receipt = gateway.execute_action(
        "send-report", payload, nonce="dispatch-8"
    )

    assert receipt.status is GatewayStatus.VERIFIED
    assert dispatched_values == ["quarterly report"]
    assert payload["body"]["value"] == "forged after validation"


def test_cyclic_payload_fails_closed_with_receipt() -> None:
    allowed_payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(allowed_payload)
    calls: list[str] = []
    registry = ToolRegistry()
    registry.register(
        "http_post",
        lambda envelope, outgoing_payload: calls.append(envelope.destination),
    )
    gateway = _fixed_gateway(graph, registry)
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    receipt = gateway.execute_action(
        "send-report", cyclic, nonce="dispatch-9"
    )

    assert receipt.status is GatewayStatus.ENVELOPE_MISMATCH
    assert receipt.executed is False
    assert receipt.error_code == "payload_not_canonicalizable"
    assert calls == []


def test_concurrent_same_nonce_reaches_adapter_at_most_once() -> None:
    payload = {"body": "quarterly report"}
    graph = _authorized_gateway_graph(payload)
    handler_entered = Event()
    release_handler = Event()
    calls_lock = Lock()
    results_lock = Lock()
    calls = 0
    results = []
    registry = ToolRegistry()

    def post(envelope, outgoing_payload):
        nonlocal calls
        with calls_lock:
            calls += 1
        handler_entered.set()
        assert release_handler.wait(timeout=2)
        return {"status": 201, "destination": envelope.destination}

    registry.register(
        "http_post",
        post,
        verifier=lambda envelope, result: True,
    )
    gateway = _fixed_gateway(graph, registry)

    def dispatch() -> None:
        receipt = gateway.execute_action(
            "send-report", payload, nonce="concurrent-nonce"
        )
        with results_lock:
            results.append(receipt)

    first = Thread(target=dispatch)
    first.start()
    assert handler_entered.wait(timeout=2)
    second = Thread(target=dispatch)
    second.start()
    second.join(timeout=2)
    release_handler.set()
    first.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert calls == 1
    assert sorted(receipt.status.value for receipt in results) == [
        GatewayStatus.REPLAY_BLOCKED.value,
        GatewayStatus.VERIFIED.value,
    ]
