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
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Iterable, Mapping

ACTION_REF_SCHEME = "draft-giskard-aeoess-action-ref-v1"
RFC3339_MILLISECONDS_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)


def validate_rfc3339_milliseconds_utc(value: str) -> str:
    """Validate the v1 timestamp shape and return it unchanged.

    The action-ref-v1 preimage requires an RFC 3339 UTC string with exactly
    millisecond precision, for example ``2026-06-18T10:40:00.123Z``.
    """

    if not isinstance(value, str) or not RFC3339_MILLISECONDS_UTC.fullmatch(value):
        raise ValueError(
            "timestamp must be RFC 3339 UTC with millisecond precision, "
            "for example 2026-06-18T10:40:00.123Z"
        )
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ValueError("timestamp contains an invalid calendar date or time") from exc
    return value


def format_rfc3339_milliseconds_utc(value: datetime) -> str:
    """Normalize an aware datetime to the v1 UTC millisecond representation."""

    if not isinstance(value, datetime):
        raise TypeError("value must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    normalized = value.astimezone(timezone.utc).isoformat(timespec="milliseconds")
    return normalized.replace("+00:00", "Z")


@dataclass(frozen=True)
class ActionRefInput:
    """Canonical input fields for the action-ref-v1 derivation."""

    agent_id: str
    action_type: str
    scope: str
    timestamp: str

    def __post_init__(self) -> None:
        for field_name in ("agent_id", "action_type", "scope"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} must be a non-empty string")
        validate_rfc3339_milliseconds_utc(self.timestamp)

    def preimage(self) -> dict[str, str]:
        """Return the versioned four-field preimage."""

        return {
            "action_type": self.action_type,
            "agent_id": self.agent_id,
            "scope": self.scope,
            "timestamp": self.timestamp,
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


def canonical_action_ref_json(value: Mapping[str, str]) -> str:
    """Serialize the restricted action-ref-v1 preimage deterministically.

    The v1 preimage contains four strings with ASCII field names. Compact,
    sorted UTF-8 JSON therefore produces the same byte sequence as JCS/RFC 8785
    for this restricted data shape.
    """

    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def derive_action_ref(
    *, agent_id: str, action_type: str, scope: str, timestamp: str
) -> str:
    """Derive a portable SHA-256 action reference from canonical metadata."""

    action_input = ActionRefInput(
        agent_id=agent_id,
        action_type=action_type,
        scope=scope,
        timestamp=timestamp,
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
