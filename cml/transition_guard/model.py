from __future__ import annotations

from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


class GraphValidationError(ValueError):
    """Raised when an invalid trust relationship is added to the graph."""


class Space(str, Enum):
    SYSTEM = "system"
    POLICY = "policy"
    AUTHORITY = "authority"
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL = "tool"
    MEMORY = "memory"
    SECRET = "secret"
    RUNTIME = "runtime"
    EXTERNAL = "external"


class NodeKind(str, Enum):
    INPUT = "input"
    CLAIM = "claim"
    INTENT = "intent"
    POLICY = "policy"
    AUTHORIZATION = "authorization"
    REVOCATION = "revocation"
    DATA = "data"
    SECRET = "secret"
    PAYLOAD = "payload"
    ACTION = "action"
    VERIFICATION = "verification"
    MEMORY_WRITE = "memory_write"


class Relation(str, Enum):
    ORIGINATED_FROM = "originated_from"
    ASSERTS = "asserts"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    DEFINES = "defines"
    AUTHORIZES = "authorizes"
    REVOKES = "revokes"
    TAINTS = "taints"
    DERIVES = "derives"
    PROPOSES = "proposes"
    TARGETS = "targets"
    VERIFIES = "verifies"
    PERSISTS_TO = "persists_to"
    TRANSITIONS_TO = "transitions_to"


class GuardVerdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class TemporalWindow:
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    revoked_at: datetime | None = None

    def is_active(self, at: datetime) -> bool:
        current = utc(at)
        if self.valid_from is not None and current < utc(self.valid_from):
            return False
        if self.valid_until is not None and current >= utc(self.valid_until):
            return False
        if self.revoked_at is not None and current >= utc(self.revoked_at):
            return False
        return True


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    kind: NodeKind
    space: Space
    attributes: Mapping[str, Any] = field(default_factory=dict)
    temporal: TemporalWindow = field(default_factory=TemporalWindow)
    trusted_for_authority: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.attributes, MappingABC):
            raise TypeError("attributes must be a mapping")
        object.__setattr__(self, "attributes", _freeze_value(self.attributes))


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relation: Relation


@dataclass(frozen=True)
class TransitionEvidence:
    action_id: str
    observed_at: str
    verdict: GuardVerdict
    reasons: tuple[str, ...]
    cause_path: tuple[str, ...]
    authority_path: tuple[str, ...]
    taint_paths: tuple[tuple[str, ...], ...]
    spaces: tuple[str, ...]
    transition: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.transition, MappingABC):
            raise TypeError("transition must be a mapping")
        object.__setattr__(self, "transition", _freeze_value(self.transition))

    @property
    def allowed(self) -> bool:
        return self.verdict is GuardVerdict.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "observed_at": self.observed_at,
            "verdict": self.verdict.value,
            "reasons": self.reasons,
            "cause_path": self.cause_path,
            "authority_path": self.authority_path,
            "taint_paths": self.taint_paths,
            "spaces": self.spaces,
            "transition": dict(self.transition),
            "allowed": self.allowed,
        }


def _freeze_value(value: Any) -> Any:
    if isinstance(value, MappingABC):
        return MappingProxyType(
            {key: _freeze_value(child) for key, child in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(child) for child in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_value(child) for child in value)
    return value


def scope_contains(scope: Any, value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if not isinstance(scope, (list, tuple, set, frozenset)):
        return False
    return value in scope


def utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
