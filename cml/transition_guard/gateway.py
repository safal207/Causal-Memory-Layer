from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any

from .graph import CausalTransitionGraph
from .model import GuardVerdict, NodeKind, TransitionEvidence, utc


class GatewayValidationError(ValueError):
    """Raised when a dispatch request cannot be bound to a graph action."""


class GatewayStatus(str, Enum):
    DENIED = "denied"
    VERIFIED = "verified"
    EXECUTED_UNVERIFIED = "executed_unverified"
    POSTCONDITION_FAILED = "postcondition_failed"
    EXECUTION_FAILED = "execution_failed"
    REPLAY_BLOCKED = "replay_blocked"
    ENVELOPE_MISMATCH = "envelope_mismatch"
    TOOL_NOT_REGISTERED = "tool_not_registered"


@dataclass(frozen=True)
class ActionEnvelope:
    """Immutable exact-action description passed from guard to dispatcher."""

    action_id: str
    operation: str
    resource: str
    destination: str
    payload_hash: str
    nonce: str
    issued_at: str

    def to_dict(self) -> dict[str, str]:
        return {
            "action_id": self.action_id,
            "destination": self.destination,
            "issued_at": self.issued_at,
            "nonce": self.nonce,
            "operation": self.operation,
            "payload_hash": self.payload_hash,
            "resource": self.resource,
        }

    @property
    def envelope_hash(self) -> str:
        return _sha256_json(self.to_dict())


@dataclass(frozen=True)
class ExecutionReceipt:
    """Audit receipt that records decisions without retaining payload data."""

    action_id: str
    envelope_hash: str
    observed_at: str
    status: GatewayStatus
    guard_evidence: TransitionEvidence
    executed: bool
    verified: bool
    result_hash: str | None = None
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "envelope_hash": self.envelope_hash,
            "observed_at": self.observed_at,
            "status": self.status.value,
            "guard_evidence": self.guard_evidence.to_dict(),
            "executed": self.executed,
            "verified": self.verified,
            "result_hash": self.result_hash,
            "error_code": self.error_code,
        }


ToolHandler = Callable[[ActionEnvelope, Any], Any]
PostconditionVerifier = Callable[[ActionEnvelope, Any], bool]


@dataclass(frozen=True)
class _RegisteredTool:
    handler: ToolHandler
    verifier: PostconditionVerifier | None = None


class ToolRegistry:
    """Operation-to-adapter registry owned by the guarded gateway."""

    def __init__(self) -> None:
        self._tools: dict[str, _RegisteredTool] = {}

    def register(
        self,
        operation: str,
        handler: ToolHandler,
        *,
        verifier: PostconditionVerifier | None = None,
    ) -> None:
        normalized = operation.strip()
        if not normalized:
            raise GatewayValidationError("operation must be non-empty")
        if normalized in self._tools:
            raise GatewayValidationError(f"duplicate tool operation: {normalized}")
        self._tools[normalized] = _RegisteredTool(handler, verifier)

    def get(self, operation: str) -> _RegisteredTool | None:
        return self._tools.get(operation)


class InMemoryReplayStore:
    """Thread-safe single-use nonce store for one gateway process."""

    def __init__(self) -> None:
        self._claimed: set[str] = set()
        self._lock = Lock()

    def claim(self, nonce: str) -> bool:
        if not nonce.strip():
            return False
        with self._lock:
            if nonce in self._claimed:
                return False
            self._claimed.add(nonce)
            return True


class GuardedToolGateway:
    """Dispatch tools only after exact binding and fail-closed graph checks."""

    def __init__(
        self,
        graph: CausalTransitionGraph,
        registry: ToolRegistry,
        *,
        replay_store: InMemoryReplayStore | None = None,
    ) -> None:
        self._graph = graph
        self._registry = registry
        self._replay_store = replay_store or InMemoryReplayStore()
        self._receipts: list[ExecutionReceipt] = []
        self._receipt_lock = Lock()

    @property
    def receipts(self) -> tuple[ExecutionReceipt, ...]:
        with self._receipt_lock:
            return tuple(self._receipts)

    def build_envelope(
        self,
        action_id: str,
        payload: Any,
        *,
        nonce: str,
        at: datetime | None = None,
    ) -> ActionEnvelope:
        action = self._graph.nodes.get(action_id)
        if action is None or action.kind is not NodeKind.ACTION:
            raise GatewayValidationError("action must exist before dispatch")
        if not nonce.strip():
            raise GatewayValidationError("nonce must be non-empty")

        payload_snapshot = _snapshot_payload(payload)
        actual_hash = payload_digest(payload_snapshot)
        expected_hash = action.attributes.get("payload_hash")
        if isinstance(expected_hash, str) and expected_hash:
            if not hmac.compare_digest(expected_hash, actual_hash):
                raise GatewayValidationError("payload does not match graph action")

        operation = action.attributes.get("operation")
        resource = action.attributes.get("resource")
        destination = action.attributes.get("destination", "")
        if not isinstance(operation, str) or not operation:
            raise GatewayValidationError("action operation must be non-empty")
        if not isinstance(resource, str) or not resource:
            raise GatewayValidationError("action resource must be non-empty")
        if destination is None:
            destination = ""
        if not isinstance(destination, str):
            raise GatewayValidationError("action destination must be a string")

        issued = utc(at or datetime.now(timezone.utc))
        return ActionEnvelope(
            action_id=action_id,
            operation=operation,
            resource=resource,
            destination=destination,
            payload_hash=actual_hash,
            nonce=nonce,
            issued_at=issued.isoformat().replace("+00:00", "Z"),
        )

    def execute_action(
        self,
        action_id: str,
        payload: Any,
        *,
        nonce: str,
        at: datetime | None = None,
    ) -> ExecutionReceipt:
        observed_at = utc(at or datetime.now(timezone.utc))
        try:
            payload_snapshot = _snapshot_payload(payload)
            envelope = self.build_envelope(
                action_id, payload_snapshot, nonce=nonce, at=observed_at
            )
        except (GatewayValidationError, TypeError, ValueError, RuntimeError) as exc:
            evidence = self._graph.evaluate(action_id, at=observed_at)
            return self._record(
                "",
                evidence,
                observed_at,
                GatewayStatus.ENVELOPE_MISMATCH,
                error_code=_validation_error_code(exc),
            )
        return self._execute_snapshot(envelope, payload_snapshot, at=observed_at)

    def execute(
        self,
        envelope: ActionEnvelope,
        payload: Any,
        *,
        at: datetime | None = None,
    ) -> ExecutionReceipt:
        observed_at = utc(at or datetime.now(timezone.utc))
        try:
            payload_snapshot = _snapshot_payload(payload)
        except (TypeError, ValueError, RuntimeError):
            evidence = self._graph.evaluate(envelope.action_id, at=observed_at)
            return self._record(
                envelope.envelope_hash,
                evidence,
                observed_at,
                GatewayStatus.ENVELOPE_MISMATCH,
                error_code="payload_not_canonicalizable",
            )
        return self._execute_snapshot(envelope, payload_snapshot, at=observed_at)

    def _execute_snapshot(
        self,
        envelope: ActionEnvelope,
        payload_snapshot: Any,
        *,
        at: datetime,
    ) -> ExecutionReceipt:
        evidence = self._graph.evaluate(envelope.action_id, at=at)

        binding_error = self._binding_error(envelope, payload_snapshot)
        if binding_error:
            return self._record(
                envelope.envelope_hash,
                evidence,
                at,
                GatewayStatus.ENVELOPE_MISMATCH,
                error_code=binding_error,
            )
        if evidence.verdict is not GuardVerdict.ALLOW:
            return self._record(
                envelope.envelope_hash,
                evidence,
                at,
                GatewayStatus.DENIED,
            )

        action = self._graph.nodes.get(envelope.action_id)
        expected_hash = (
            action.attributes.get("payload_hash") if action is not None else None
        )
        if not isinstance(expected_hash, str) or not expected_hash:
            return self._record(
                envelope.envelope_hash,
                evidence,
                at,
                GatewayStatus.ENVELOPE_MISMATCH,
                error_code="allowed_action_missing_payload_hash",
            )

        tool = self._registry.get(envelope.operation)
        if tool is None:
            return self._record(
                envelope.envelope_hash,
                evidence,
                at,
                GatewayStatus.TOOL_NOT_REGISTERED,
                error_code="tool_not_registered",
            )
        if not self._replay_store.claim(envelope.nonce):
            return self._record(
                envelope.envelope_hash,
                evidence,
                at,
                GatewayStatus.REPLAY_BLOCKED,
                error_code="nonce_already_used",
            )

        try:
            result = tool.handler(envelope, payload_snapshot)
        except Exception as exc:  # noqa: BLE001 - adapter boundary
            return self._record(
                envelope.envelope_hash,
                evidence,
                at,
                GatewayStatus.EXECUTION_FAILED,
                executed=True,
                error_code=type(exc).__name__,
            )

        try:
            result_snapshot = _snapshot_payload(result)
            result_hash = payload_digest(result_snapshot)
        except (TypeError, ValueError, RuntimeError):
            return self._record(
                envelope.envelope_hash,
                evidence,
                at,
                GatewayStatus.EXECUTED_UNVERIFIED,
                executed=True,
                error_code="result_not_canonicalizable",
            )
        if tool.verifier is None:
            return self._record(
                envelope.envelope_hash,
                evidence,
                at,
                GatewayStatus.EXECUTED_UNVERIFIED,
                executed=True,
                result_hash=result_hash,
            )
        try:
            verified = bool(tool.verifier(envelope, result_snapshot))
        except Exception as exc:  # noqa: BLE001 - verification fails closed
            return self._record(
                envelope.envelope_hash,
                evidence,
                at,
                GatewayStatus.POSTCONDITION_FAILED,
                executed=True,
                result_hash=result_hash,
                error_code=type(exc).__name__,
            )
        return self._record(
            envelope.envelope_hash,
            evidence,
            at,
            GatewayStatus.VERIFIED if verified else GatewayStatus.POSTCONDITION_FAILED,
            executed=True,
            verified=verified,
            result_hash=result_hash,
            error_code=None if verified else "postcondition_not_satisfied",
        )

    def _binding_error(
        self, envelope: ActionEnvelope, payload: Any
    ) -> str | None:
        action = self._graph.nodes.get(envelope.action_id)
        if action is None or action.kind is not NodeKind.ACTION:
            return "action_not_found"
        destination = action.attributes.get("destination", "")
        if destination is None:
            destination = ""
        expected = (
            action.attributes.get("operation"),
            action.attributes.get("resource"),
            destination,
        )
        actual = (envelope.operation, envelope.resource, envelope.destination)
        if expected != actual:
            return "envelope_does_not_match_graph_action"
        expected_hash = action.attributes.get("payload_hash")
        if isinstance(expected_hash, str) and expected_hash:
            if not hmac.compare_digest(expected_hash, envelope.payload_hash):
                return "envelope_does_not_match_graph_payload"
        if not hmac.compare_digest(
            envelope.payload_hash, payload_digest(payload)
        ):
            return "payload_hash_mismatch"
        return None

    def _record(
        self,
        envelope_hash: str,
        evidence: TransitionEvidence,
        at: datetime,
        status: GatewayStatus,
        *,
        executed: bool = False,
        verified: bool = False,
        result_hash: str | None = None,
        error_code: str | None = None,
    ) -> ExecutionReceipt:
        receipt = ExecutionReceipt(
            action_id=evidence.action_id,
            envelope_hash=envelope_hash,
            observed_at=at.isoformat().replace("+00:00", "Z"),
            status=status,
            guard_evidence=evidence,
            executed=executed,
            verified=verified,
            result_hash=result_hash,
            error_code=error_code,
        )
        with self._receipt_lock:
            self._receipts.append(receipt)
        return receipt


def payload_digest(value: Any) -> str:
    """Return a deterministic, type-preserving SHA-256 payload digest."""

    return _sha256_json(_canonicalize(value))


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonicalize(value: Any) -> Any:
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if isinstance(value, int):
        return {"type": "int", "value": str(value)}
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise TypeError("non-finite floats are not supported")
        return {"type": "float", "value": value.hex()}
    if isinstance(value, str):
        return {"type": "str", "value": value}
    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "value": base64.b64encode(value).decode("ascii"),
        }
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("payload mappings require string keys")
            result[key] = _canonicalize(child)
        return {"type": "mapping", "value": result}
    if isinstance(value, list):
        return {
            "type": "list",
            "value": [_canonicalize(child) for child in value],
        }
    if isinstance(value, tuple):
        return {
            "type": "tuple",
            "value": [_canonicalize(child) for child in value],
        }
    raise TypeError(f"unsupported payload type: {type(value).__name__}")


def _snapshot_payload(value: Any, *, _seen: set[int] | None = None) -> Any:
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    seen = _seen if _seen is not None else set()
    object_id = id(value)
    if object_id in seen:
        raise TypeError("cyclic payloads are not supported")
    seen.add(object_id)
    try:
        if isinstance(value, Mapping):
            snapshot: dict[str, Any] = {}
            for key, child in value.items():
                if not isinstance(key, str):
                    raise TypeError("payload mappings require string keys")
                snapshot[key] = _snapshot_payload(child, _seen=seen)
            return snapshot
        if isinstance(value, list):
            return [_snapshot_payload(child, _seen=seen) for child in value]
        if isinstance(value, tuple):
            return tuple(_snapshot_payload(child, _seen=seen) for child in value)
        raise TypeError(f"unsupported payload type: {type(value).__name__}")
    finally:
        seen.remove(object_id)


def _validation_error_code(exc: Exception) -> str:
    if isinstance(exc, GatewayValidationError):
        return str(exc)
    return "payload_not_canonicalizable"
