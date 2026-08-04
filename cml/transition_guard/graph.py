from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Mapping

from .model import (
    GraphEdge,
    GraphNode,
    GraphValidationError,
    GuardVerdict,
    NodeKind,
    Relation,
    Space,
    TransitionEvidence,
    scope_contains,
    utc,
)


class CausalTransitionGraph:
    """Fail-closed cause-space-time authorization graph for tool transitions."""

    _TAINT_RELATIONS = {
        Relation.TAINTS,
        Relation.DERIVES,
        Relation.PROPOSES,
        Relation.TARGETS,
        Relation.PERSISTS_TO,
    }

    def __init__(
        self,
        *,
        trusted_policy_sources: Iterable[str] = ("policy-engine",),
        trusted_authority_sources: Iterable[str] = ("authority-service",),
    ) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._trusted_policy_sources = frozenset(trusted_policy_sources)
        self._trusted_authority_sources = frozenset(trusted_authority_sources)

    @property
    def nodes(self) -> Mapping[str, GraphNode]:
        return dict(self._nodes)

    @property
    def edges(self) -> tuple[GraphEdge, ...]:
        return tuple(self._edges)

    def add_node(self, node: GraphNode) -> None:
        if not node.node_id.strip():
            raise GraphValidationError("node_id must be non-empty")
        if node.node_id in self._nodes:
            raise GraphValidationError(f"duplicate node_id: {node.node_id}")
        self._validate_authority_node(node)
        self._nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source not in self._nodes or edge.target not in self._nodes:
            raise GraphValidationError("edge endpoints must already exist")
        self._validate_authority_edge(edge)
        if edge in self._edges:
            raise GraphValidationError("duplicate edge")
        self._edges.append(edge)

    def evaluate(
        self, action_id: str, *, at: datetime | None = None
    ) -> TransitionEvidence:
        observed_at = utc(at or datetime.now(timezone.utc))
        action = self._nodes.get(action_id)
        if action is None or action.kind is not NodeKind.ACTION:
            return self._evidence(
                action_id=action_id,
                at=observed_at,
                verdict=GuardVerdict.DENY,
                reasons=("ACTION_NOT_FOUND",),
            )

        reasons: list[str] = []
        cause_path = self._intent_path(action_id, observed_at)
        if not cause_path:
            reasons.append("NO_ACTIVE_INTENT_PATH")

        authority_path, authorization = self._authority_path(action, observed_at)
        if authorization is None:
            reasons.append("NO_TRUSTED_AUTHORITY_PATH")
        else:
            reasons.extend(self._scope_violations(action, authorization))
            if self._is_revoked(authorization.node_id, observed_at):
                reasons.append("AUTHORIZATION_REVOKED")

        taint_paths = self._secret_taint_paths(action_id, observed_at)
        external = bool(action.attributes.get("external_boundary", False))
        if taint_paths and external:
            secret_egress_allowed = bool(
                authorization
                and authorization.attributes.get("allow_secret_egress") is True
                and self._secret_scope_matches(action, authorization)
            )
            if not secret_egress_allowed:
                reasons.append("SECRET_TAINT_CROSSES_EXTERNAL_BOUNDARY")

        destination = action.attributes.get("destination")
        if external and not isinstance(destination, str):
            reasons.append("EXTERNAL_DESTINATION_MISSING")

        verdict = GuardVerdict.DENY if reasons else GuardVerdict.ALLOW
        return self._evidence(
            action_id=action_id,
            at=observed_at,
            verdict=verdict,
            reasons=tuple(dict.fromkeys(reasons)),
            cause_path=cause_path,
            authority_path=authority_path,
            taint_paths=taint_paths,
            action=action,
        )

    def _validate_authority_node(self, node: GraphNode) -> None:
        source = node.attributes.get("source")
        if node.kind is NodeKind.POLICY:
            if node.space not in {Space.POLICY, Space.SYSTEM}:
                raise GraphValidationError(
                    "policy nodes must live in policy or system space"
                )
            if (
                node.trusted_for_authority
                and source not in self._trusted_policy_sources
            ):
                raise GraphValidationError("unrecognized trusted policy source")
        elif node.kind is NodeKind.AUTHORIZATION:
            if node.space is not Space.AUTHORITY:
                raise GraphValidationError(
                    "authorization nodes must live in authority space"
                )
            if (
                node.trusted_for_authority
                and source not in self._trusted_authority_sources
            ):
                raise GraphValidationError("unrecognized trusted authority source")
        elif node.kind is NodeKind.REVOCATION:
            if node.space is not Space.AUTHORITY:
                raise GraphValidationError(
                    "revocation nodes must live in authority space"
                )
            if source not in self._trusted_authority_sources:
                raise GraphValidationError("unrecognized trusted revocation source")
            if node.trusted_for_authority:
                raise GraphValidationError("revocation nodes do not grant authority")
        elif node.trusted_for_authority:
            raise GraphValidationError(
                "only policy and authorization nodes may be trusted for authority"
            )

    def _validate_authority_edge(self, edge: GraphEdge) -> None:
        source = self._nodes[edge.source]
        target = self._nodes[edge.target]
        if edge.relation is Relation.DEFINES:
            if (
                not self._is_trusted_policy(source)
                or target.kind is not NodeKind.AUTHORIZATION
            ):
                raise GraphValidationError(
                    "DEFINES requires a trusted policy and authorization target"
                )
        elif edge.relation is Relation.AUTHORIZES:
            if (
                not self._is_trusted_authorization(source)
                or target.kind is not NodeKind.ACTION
            ):
                raise GraphValidationError(
                    "AUTHORIZES requires a trusted authorization and action target"
                )
        elif edge.relation is Relation.REVOKES:
            if source.kind not in {NodeKind.REVOCATION, NodeKind.POLICY}:
                raise GraphValidationError(
                    "REVOKES requires a revocation or policy source"
                )
            if target.kind is not NodeKind.AUTHORIZATION:
                raise GraphValidationError(
                    "REVOKES must target an authorization"
                )

    def _is_trusted_policy(self, node: GraphNode) -> bool:
        return (
            node.kind is NodeKind.POLICY
            and node.trusted_for_authority
            and node.attributes.get("source") in self._trusted_policy_sources
        )

    def _is_trusted_authorization(self, node: GraphNode) -> bool:
        return (
            node.kind is NodeKind.AUTHORIZATION
            and node.trusted_for_authority
            and node.attributes.get("source") in self._trusted_authority_sources
        )

    def _incoming(
        self, target: str, relation: Relation | None = None
    ) -> list[GraphEdge]:
        return [
            edge
            for edge in self._edges
            if edge.target == target
            and (relation is None or edge.relation is relation)
        ]

    def _outgoing(
        self, source: str, relations: set[Relation] | None = None
    ) -> list[GraphEdge]:
        return [
            edge
            for edge in self._edges
            if edge.source == source
            and (relations is None or edge.relation in relations)
        ]

    def _intent_path(self, action_id: str, at: datetime) -> tuple[str, ...]:
        for edge in self._incoming(action_id, Relation.PROPOSES):
            node = self._nodes[edge.source]
            if node.kind is NodeKind.INTENT and node.temporal.is_active(at):
                return (node.node_id, action_id)
        return ()

    def _authority_path(
        self, action: GraphNode, at: datetime
    ) -> tuple[tuple[str, ...], GraphNode | None]:
        for auth_edge in self._incoming(action.node_id, Relation.AUTHORIZES):
            authorization = self._nodes[auth_edge.source]
            if not self._is_trusted_authorization(authorization):
                continue
            if not authorization.temporal.is_active(at):
                continue
            for policy_edge in self._incoming(
                authorization.node_id, Relation.DEFINES
            ):
                policy = self._nodes[policy_edge.source]
                if self._is_trusted_policy(policy) and policy.temporal.is_active(at):
                    return (
                        policy.node_id,
                        authorization.node_id,
                        action.node_id,
                    ), authorization
        return (), None

    def _is_revoked(self, authorization_id: str, at: datetime) -> bool:
        for edge in self._incoming(authorization_id, Relation.REVOKES):
            revocation = self._nodes[edge.source]
            start = revocation.temporal.valid_from
            if start is None or utc(start) <= at:
                return True
        return False

    def _scope_violations(
        self, action: GraphNode, authorization: GraphNode
    ) -> list[str]:
        violations: list[str] = []
        operation = action.attributes.get("operation")
        resource = action.attributes.get("resource")
        destination = action.attributes.get("destination")
        if not scope_contains(authorization.attributes.get("actions"), operation):
            violations.append("ACTION_OUT_OF_SCOPE")
        if not scope_contains(authorization.attributes.get("resources"), resource):
            violations.append("RESOURCE_OUT_OF_SCOPE")
        if action.attributes.get("external_boundary", False) and not scope_contains(
            authorization.attributes.get("destinations"), destination
        ):
            violations.append("DESTINATION_OUT_OF_SCOPE")
        return violations

    def _secret_scope_matches(
        self, action: GraphNode, authorization: GraphNode
    ) -> bool:
        return scope_contains(
            authorization.attributes.get("secret_resources"),
            action.attributes.get("resource"),
        ) and scope_contains(
            authorization.attributes.get("destinations"),
            action.attributes.get("destination"),
        )

    def _secret_taint_paths(
        self, action_id: str, at: datetime
    ) -> tuple[tuple[str, ...], ...]:
        paths: list[tuple[str, ...]] = []
        for node in self._nodes.values():
            if node.kind is not NodeKind.SECRET or not node.temporal.is_active(at):
                continue
            path = self._find_path(node.node_id, action_id, self._TAINT_RELATIONS)
            if path:
                paths.append(path)
        return tuple(sorted(paths))

    def _find_path(
        self, source: str, target: str, relations: set[Relation]
    ) -> tuple[str, ...]:
        stack: list[tuple[str, tuple[str, ...]]] = [(source, (source,))]
        visited: set[str] = set()
        while stack:
            current, path = stack.pop()
            if current == target:
                return path
            if current in visited:
                continue
            visited.add(current)
            for edge in reversed(self._outgoing(current, relations)):
                if edge.target not in path:
                    stack.append((edge.target, (*path, edge.target)))
        return ()

    def _evidence(
        self,
        *,
        action_id: str,
        at: datetime,
        verdict: GuardVerdict,
        reasons: tuple[str, ...],
        cause_path: tuple[str, ...] = (),
        authority_path: tuple[str, ...] = (),
        taint_paths: tuple[tuple[str, ...], ...] = (),
        action: GraphNode | None = None,
    ) -> TransitionEvidence:
        relevant_ids = set(cause_path) | set(authority_path)
        for path in taint_paths:
            relevant_ids.update(path)
        relevant_ids.add(action_id)
        spaces = tuple(
            sorted(
                {
                    self._nodes[node_id].space.value
                    for node_id in relevant_ids
                    if node_id in self._nodes
                }
            )
        )
        state_from = (
            str(action.attributes.get("state_from", "proposed"))
            if action
            else "unknown"
        )
        proposed_to = (
            str(action.attributes.get("state_to", "blocked"))
            if action
            else "blocked"
        )
        transition = {
            "from": state_from,
            "proposed_to": proposed_to,
            "actual_to": (
                proposed_to if verdict is GuardVerdict.ALLOW else state_from
            ),
        }
        return TransitionEvidence(
            action_id=action_id,
            observed_at=at.isoformat().replace("+00:00", "Z"),
            verdict=verdict,
            reasons=reasons,
            cause_path=cause_path,
            authority_path=authority_path,
            taint_paths=taint_paths,
            spaces=spaces,
            transition=transition,
        )
