"""Deterministic action identities and structural reference validation.

This module intentionally separates three guarantees:

* ``action_ref`` provides deterministic identity stability;
* graph validation checks whether parent references are structurally sound;
* signatures or external anchors provide authorship/tamper evidence.

The helper is dependency-free and does not perform signing, anchoring, policy
checks, or runtime enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Iterable, Mapping

ACTION_REF_SCHEME = "draft-giskard-aeoess-action-ref-v1"


@dataclass(frozen=True)
class ActionRefInput:
    """Canonical input fields for the action-ref-v1 derivation."""

    agent_id: str
    action_type: str
    scope: str
    timestamp_ms: int

    def __post_init__(self) -> None:
        for field_name in ("agent_id", "action_type", "scope"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} must be a non-empty string")
        if isinstance(self.timestamp_ms, bool) or not isinstance(self.timestamp_ms, int):
            raise TypeError("timestamp_ms must be an integer")
        if self.timestamp_ms < 0:
            raise ValueError("timestamp_ms must be non-negative")

    def preimage(self) -> dict[str, str | int]:
        """Return the versioned four-field preimage."""

        return {
            "action_type": self.action_type,
            "agent_id": self.agent_id,
            "scope": self.scope,
            "timestamp_ms": self.timestamp_ms,
        }


@dataclass(frozen=True)
class ActionRefNode:
    """A node in a deterministic action-reference graph.

    ``signature`` and ``anchor`` are deliberately opaque sidecar values. They
    are not considered by structural graph validation.
    """

    action_ref: str
    parent_action_ref: str | None = None
    action_ref_scheme: str = ACTION_REF_SCHEME
    signature: str | None = None
    anchor: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.action_ref, str) or not self.action_ref:
            raise ValueError("action_ref must be a non-empty string")
        if self.parent_action_ref is not None and (
            not isinstance(self.parent_action_ref, str) or not self.parent_action_ref
        ):
            raise ValueError("parent_action_ref must be null or a non-empty string")
        if not isinstance(self.action_ref_scheme, str) or not self.action_ref_scheme:
            raise ValueError("action_ref_scheme must be a non-empty string")


@dataclass(frozen=True)
class ActionRefFinding:
    """A deterministic structural finding for an action-reference graph."""

    code: str
    action_ref: str
    message: str


@dataclass(frozen=True)
class ActionRefValidationResult:
    """Validation result returned by :func:`validate_action_ref_graph`."""

    findings: tuple[ActionRefFinding, ...]

    def passed(self) -> bool:
        return not self.findings


def canonical_action_ref_json(value: Mapping[str, str | int]) -> str:
    """Serialize the restricted action-ref-v1 preimage deterministically.

    The v1 preimage contains only strings and one integer, so this compact,
    sorted UTF-8 JSON representation avoids float and object-order ambiguity.
    Consumers claiming full RFC 8785 compatibility should verify against a JCS
    implementation and the draft's conformance vectors.
    """

    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def derive_action_ref(
    *, agent_id: str, action_type: str, scope: str, timestamp_ms: int
) -> str:
    """Derive a portable SHA-256 action reference from canonical metadata."""

    action_input = ActionRefInput(
        agent_id=agent_id,
        action_type=action_type,
        scope=scope,
        timestamp_ms=timestamp_ms,
    )
    canonical = canonical_action_ref_json(action_input.preimage())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_action_ref_graph(
    nodes: Iterable[ActionRefNode],
) -> ActionRefValidationResult:
    """Validate uniqueness, parent resolution, and acyclicity.

    Signatures and external anchors are intentionally ignored: they provide a
    different guarantee and must not change the structural audit result.
    """

    materialized = list(nodes)
    findings: list[ActionRefFinding] = []
    by_ref: dict[str, ActionRefNode] = {}

    for node in materialized:
        if node.action_ref in by_ref:
            findings.append(
                ActionRefFinding(
                    code="CML-ACTION-REF-DUPLICATE",
                    action_ref=node.action_ref,
                    message=f"duplicate action_ref: {node.action_ref}",
                )
            )
            continue
        by_ref[node.action_ref] = node

    for node in materialized:
        parent = node.parent_action_ref
        if parent is not None and parent not in by_ref:
            findings.append(
                ActionRefFinding(
                    code="CML-ACTION-REF-MISSING-PARENT",
                    action_ref=node.action_ref,
                    message=f"parent_action_ref does not resolve: {parent}",
                )
            )

    state: dict[str, int] = {}
    reported_cycles: set[str] = set()

    def visit(action_ref: str) -> None:
        current_state = state.get(action_ref, 0)
        if current_state == 2:
            return
        if current_state == 1:
            if action_ref not in reported_cycles:
                findings.append(
                    ActionRefFinding(
                        code="CML-ACTION-REF-CYCLE",
                        action_ref=action_ref,
                        message=f"cycle detected at action_ref: {action_ref}",
                    )
                )
                reported_cycles.add(action_ref)
            return

        state[action_ref] = 1
        parent = by_ref[action_ref].parent_action_ref
        if parent is not None and parent in by_ref:
            visit(parent)
        state[action_ref] = 2

    for action_ref in by_ref:
        visit(action_ref)

    findings.sort(key=lambda item: (item.code, item.action_ref, item.message))
    return ActionRefValidationResult(findings=tuple(findings))
