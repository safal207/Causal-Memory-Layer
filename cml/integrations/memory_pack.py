"""Portable, content-addressed decision memory packages.

``MemoryPackV1`` is an advisory interchange contract. It binds a privacy
manifest, decision graph, evidence references, and declared redactions into a
canonical SHA-256 identity. A valid pack proves deterministic integrity of the
supplied package only; it does not prove that observations are true, evidence
is independent, or the selected path is globally optimal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Literal, Mapping, Sequence

MEMORY_PACK_SCHEMA = "cml-memory-pack-v1"
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_HEX = re.compile(r"^[0-9a-f]{40}$")
STABLE_TOKEN = re.compile(r"^[A-Za-z0-9._:/-]+$")
RFC3339_MILLISECONDS_UTC = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)

VISIBILITIES = frozenset({"private", "team", "partner", "public"})
NODE_KINDS = frozenset(
    {
        "situation",
        "cause",
        "constraint",
        "option",
        "action",
        "check",
        "outcome",
        "lesson",
        "evidence",
    }
)
NODE_STATUSES = frozenset(
    {"observed", "proposed", "tested", "verified", "failed", "superseded"}
)
EDGE_RELATIONS = frozenset(
    {
        "causes",
        "supports",
        "contradicts",
        "requires",
        "blocks",
        "mitigates",
        "leads_to",
        "selected_over",
        "supersedes",
    }
)
EVIDENCE_KINDS = frozenset(
    {"commit", "workflow_run", "artifact", "review", "test", "document"}
)

MANIFEST_FIELDS = frozenset(
    {
        "project",
        "source_repository",
        "source_commit",
        "created_at",
        "visibility",
        "license",
        "contains_private_data",
        "merge_authority",
        "execution_authority",
        "description",
    }
)
NODE_FIELDS = frozenset(
    {"id", "kind", "label", "status", "confidence", "attributes"}
)
EDGE_FIELDS = frozenset(
    {"id", "source", "target", "relation", "strength", "evidence_ids"}
)
EVIDENCE_FIELDS = frozenset(
    {"id", "kind", "digest", "locator", "description"}
)
REDACTION_FIELDS = frozenset({"path", "reason"})
GRAPH_FIELDS = frozenset({"nodes", "edges", "selected_path"})
TOP_LEVEL_FIELDS = frozenset(
    {"schema_version", "pack_id", "manifest", "graph", "evidence", "redactions"}
)

MemoryVisibility = Literal["private", "team", "partner", "public"]
MemoryNodeKind = Literal[
    "situation",
    "cause",
    "constraint",
    "option",
    "action",
    "check",
    "outcome",
    "lesson",
    "evidence",
]
MemoryNodeStatus = Literal[
    "observed", "proposed", "tested", "verified", "failed", "superseded"
]
MemoryEdgeRelation = Literal[
    "causes",
    "supports",
    "contradicts",
    "requires",
    "blocks",
    "mitigates",
    "leads_to",
    "selected_over",
    "supersedes",
]
MemoryEvidenceKind = Literal[
    "commit", "workflow_run", "artifact", "review", "test", "document"
]


def _validate_unicode_scalar_string(value: str, *, label: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError(f"{label} must contain only Unicode scalar values")
    return value


def _validate_non_empty_string(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    _validate_unicode_scalar_string(value, label=label)
    if value != value.strip():
        raise ValueError(f"{label} must not contain leading or trailing whitespace")
    return value


def _validate_token(value: object, *, label: str) -> str:
    text = _validate_non_empty_string(value, label=label)
    if not STABLE_TOKEN.fullmatch(text):
        raise ValueError(
            f"{label} must use the ASCII token charset [A-Za-z0-9._:/-]"
        )
    return text


def _validate_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not SHA256_HEX.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase 64-character SHA-256 digest")
    return value


def _validate_commit(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not GIT_COMMIT_HEX.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase 40-character Git commit")
    return value


def _validate_timestamp(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not RFC3339_MILLISECONDS_UTC.fullmatch(value):
        raise ValueError(f"{label} must be RFC3339 UTC with exact millisecond precision")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError(f"{label} must be a real RFC3339 UTC timestamp") from exc
    return value


def _validate_bool(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a boolean")
    return value


def _validate_int_range(
    value: object, *, label: str, minimum: int, maximum: int
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _freeze_json(value: Any, *, path: str) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return _validate_unicode_scalar_string(value, label=path)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} keys must be strings")
            _validate_unicode_scalar_string(key, label=f"{path} key")
            frozen[key] = _freeze_json(item, path=f"{path}.{key}")
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(
            _freeze_json(item, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        )
    raise ValueError(f"{path} contains a non-JSON value: {type(value).__name__}")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _validate_unicode_scalar_string(key, label="JSON object key")
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _require_exact_fields(
    payload: Mapping[str, Any], *, expected: frozenset[str], label: str
) -> None:
    if any(not isinstance(key, str) for key in payload):
        raise ValueError(f"{label} keys must be strings")
    observed = frozenset(payload)
    missing = sorted(expected - observed)
    unknown = sorted(observed - expected)
    if missing:
        raise ValueError(f"{label} is missing fields: {', '.join(missing)}")
    if unknown:
        raise ValueError(f"{label} contains unknown fields: {', '.join(unknown)}")


def _require_sequence(value: object, *, label: str) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{label} must be a JSON array")
    return value


@dataclass(frozen=True)
class MemoryPackManifestV1:
    project: str
    source_repository: str
    source_commit: str
    created_at: str
    visibility: MemoryVisibility
    license: str
    contains_private_data: bool
    merge_authority: bool
    execution_authority: bool
    description: str

    def __post_init__(self) -> None:
        _validate_non_empty_string(self.project, label="project")
        _validate_non_empty_string(self.source_repository, label="source_repository")
        _validate_commit(self.source_commit, label="source_commit")
        _validate_timestamp(self.created_at, label="created_at")
        if not isinstance(self.visibility, str) or self.visibility not in VISIBILITIES:
            raise ValueError("visibility must be private, team, partner, or public")
        _validate_token(self.license, label="license")
        _validate_bool(self.contains_private_data, label="contains_private_data")
        _validate_bool(self.merge_authority, label="merge_authority")
        _validate_bool(self.execution_authority, label="execution_authority")
        if self.merge_authority:
            raise ValueError("memory packs must not grant merge authority")
        if self.execution_authority:
            raise ValueError("memory packs must not grant execution authority")
        _validate_non_empty_string(self.description, label="description")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "source_repository": self.source_repository,
            "source_commit": self.source_commit,
            "created_at": self.created_at,
            "visibility": self.visibility,
            "license": self.license,
            "contains_private_data": self.contains_private_data,
            "merge_authority": self.merge_authority,
            "execution_authority": self.execution_authority,
            "description": self.description,
        }


@dataclass(frozen=True)
class MemoryNodeV1:
    id: str
    kind: MemoryNodeKind
    label: str
    status: MemoryNodeStatus
    confidence: int
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_token(self.id, label="node id")
        if not isinstance(self.kind, str) or self.kind not in NODE_KINDS:
            raise ValueError(f"node kind must be one of: {', '.join(sorted(NODE_KINDS))}")
        _validate_non_empty_string(self.label, label="node label")
        if not isinstance(self.status, str) or self.status not in NODE_STATUSES:
            raise ValueError(
                f"node status must be one of: {', '.join(sorted(NODE_STATUSES))}"
            )
        _validate_int_range(
            self.confidence, label="node confidence", minimum=0, maximum=100
        )
        if not isinstance(self.attributes, Mapping):
            raise TypeError("node attributes must be a JSON object")
        object.__setattr__(
            self,
            "attributes",
            _freeze_json(self.attributes, path=f"node[{self.id}].attributes"),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "confidence": self.confidence,
            "attributes": _thaw_json(self.attributes),
        }


@dataclass(frozen=True)
class MemoryEdgeV1:
    id: str
    source: str
    target: str
    relation: MemoryEdgeRelation
    strength: int
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_token(self.id, label="edge id")
        _validate_token(self.source, label="edge source")
        _validate_token(self.target, label="edge target")
        if self.source == self.target:
            raise ValueError("memory graph edges must not be self-loops")
        if not isinstance(self.relation, str) or self.relation not in EDGE_RELATIONS:
            raise ValueError(
                f"edge relation must be one of: {', '.join(sorted(EDGE_RELATIONS))}"
            )
        _validate_int_range(
            self.strength, label="edge strength", minimum=0, maximum=100
        )
        raw_evidence_ids = tuple(self.evidence_ids)
        for evidence_id in raw_evidence_ids:
            _validate_token(evidence_id, label="edge evidence id")
        normalized = tuple(sorted(raw_evidence_ids))
        if len(set(normalized)) != len(normalized):
            raise ValueError("edge evidence_ids must be unique")
        object.__setattr__(self, "evidence_ids", normalized)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "strength": self.strength,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class MemoryEvidenceV1:
    id: str
    kind: MemoryEvidenceKind
    digest: str
    locator: str
    description: str

    def __post_init__(self) -> None:
        _validate_token(self.id, label="evidence id")
        if not isinstance(self.kind, str) or self.kind not in EVIDENCE_KINDS:
            raise ValueError(
                f"evidence kind must be one of: {', '.join(sorted(EVIDENCE_KINDS))}"
            )
        _validate_digest(self.digest, label="evidence digest")
        _validate_non_empty_string(self.locator, label="evidence locator")
        _validate_non_empty_string(self.description, label="evidence description")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "digest": self.digest,
            "locator": self.locator,
            "description": self.description,
        }


@dataclass(frozen=True)
class MemoryRedactionV1:
    path: str
    reason: str

    def __post_init__(self) -> None:
        _validate_non_empty_string(self.path, label="redaction path")
        _validate_non_empty_string(self.reason, label="redaction reason")

    def to_mapping(self) -> dict[str, str]:
        return {"path": self.path, "reason": self.reason}


@dataclass(frozen=True)
class MemoryGraphV1:
    nodes: tuple[MemoryNodeV1, ...]
    edges: tuple[MemoryEdgeV1, ...]
    selected_path: tuple[str, ...]

    def __post_init__(self) -> None:
        if not all(isinstance(node, MemoryNodeV1) for node in self.nodes):
            raise TypeError("nodes must contain only MemoryNodeV1 values")
        if not all(isinstance(edge, MemoryEdgeV1) for edge in self.edges):
            raise TypeError("edges must contain only MemoryEdgeV1 values")
        nodes = tuple(sorted(self.nodes, key=lambda node: node.id))
        edges = tuple(sorted(self.edges, key=lambda edge: edge.id))
        node_ids = [node.id for node in nodes]
        edge_ids = [edge.id for edge in edges]
        if not nodes:
            raise ValueError("memory graph must contain at least one node")
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("memory graph node ids must be unique")
        if len(set(edge_ids)) != len(edge_ids):
            raise ValueError("memory graph edge ids must be unique")
        node_id_set = set(node_ids)
        for edge in edges:
            if edge.source not in node_id_set or edge.target not in node_id_set:
                raise ValueError(f"edge {edge.id!r} references a missing node")
        path = tuple(self.selected_path)
        if not path:
            raise ValueError("selected_path must contain at least one node id")
        for node_id in path:
            _validate_token(node_id, label="selected_path node id")
        if len(set(path)) != len(path):
            raise ValueError("selected_path must not repeat node ids")
        if any(node_id not in node_id_set for node_id in path):
            raise ValueError("selected_path references a missing node")
        node_by_id = {node.id: node for node in nodes}
        if node_by_id[path[0]].kind != "situation":
            raise ValueError("selected_path must start with a situation node")
        if node_by_id[path[-1]].kind not in {"outcome", "lesson"}:
            raise ValueError("selected_path must end with an outcome or lesson node")
        directed_pairs = {(edge.source, edge.target) for edge in edges}
        for source, target in zip(path, path[1:]):
            if (source, target) not in directed_pairs:
                raise ValueError(
                    f"selected_path step {source!r} -> {target!r} has no graph edge"
                )
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)
        object.__setattr__(self, "selected_path", path)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_mapping() for node in self.nodes],
            "edges": [edge.to_mapping() for edge in self.edges],
            "selected_path": list(self.selected_path),
        }


@dataclass(frozen=True)
class MemoryPackV1:
    pack_id: str
    manifest: MemoryPackManifestV1
    graph: MemoryGraphV1
    evidence: tuple[MemoryEvidenceV1, ...] = ()
    redactions: tuple[MemoryRedactionV1, ...] = ()
    schema_version: str = MEMORY_PACK_SCHEMA

    __hash__ = None

    def __post_init__(self) -> None:
        if self.schema_version != MEMORY_PACK_SCHEMA:
            raise ValueError(f"schema_version must be {MEMORY_PACK_SCHEMA!r}")
        _validate_digest(self.pack_id, label="pack_id")
        if not isinstance(self.manifest, MemoryPackManifestV1):
            raise TypeError("manifest must be MemoryPackManifestV1")
        if not isinstance(self.graph, MemoryGraphV1):
            raise TypeError("graph must be MemoryGraphV1")
        if not all(isinstance(item, MemoryEvidenceV1) for item in self.evidence):
            raise TypeError("evidence must contain only MemoryEvidenceV1 values")
        if not all(isinstance(item, MemoryRedactionV1) for item in self.redactions):
            raise TypeError("redactions must contain only MemoryRedactionV1 values")
        evidence = tuple(sorted(self.evidence, key=lambda item: item.id))
        redactions = tuple(
            sorted(self.redactions, key=lambda item: (item.path, item.reason))
        )
        evidence_ids = [item.id for item in evidence]
        redaction_paths = [item.path for item in redactions]
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("memory pack evidence ids must be unique")
        if len(set(redaction_paths)) != len(redaction_paths):
            raise ValueError("memory pack redaction paths must be unique")
        known_evidence = set(evidence_ids)
        for edge in self.graph.edges:
            missing = sorted(set(edge.evidence_ids) - known_evidence)
            if missing:
                raise ValueError(
                    f"edge {edge.id!r} references missing evidence: {', '.join(missing)}"
                )
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "redactions", redactions)

    def same_authoritative_identity(self, other: object) -> bool:
        if not isinstance(other, MemoryPackV1):
            return False
        return (
            self.pack_id
            == derive_memory_pack_id(
                self.manifest, self.graph, self.evidence, self.redactions
            )
            and other.pack_id
            == derive_memory_pack_id(
                other.manifest, other.graph, other.evidence, other.redactions
            )
            and self.schema_version == other.schema_version
            and self.pack_id == other.pack_id
            and self.manifest == other.manifest
            and self.graph == other.graph
            and self.evidence == other.evidence
            and self.redactions == other.redactions
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "pack_id": self.pack_id,
            "manifest": self.manifest.to_mapping(),
            "graph": self.graph.to_mapping(),
            "evidence": [item.to_mapping() for item in self.evidence],
            "redactions": [item.to_mapping() for item in self.redactions],
        }


@dataclass(frozen=True)
class MemoryPackFinding:
    code: str
    message: str


@dataclass(frozen=True)
class MemoryPackVerificationResult:
    findings: tuple[MemoryPackFinding, ...]
    expected_pack_id: str

    def passed(self) -> bool:
        return not self.findings


def _canonical_payload(
    manifest: MemoryPackManifestV1,
    graph: MemoryGraphV1,
    evidence: Sequence[MemoryEvidenceV1],
    redactions: Sequence[MemoryRedactionV1],
) -> dict[str, Any]:
    if not isinstance(manifest, MemoryPackManifestV1):
        raise TypeError("manifest must be MemoryPackManifestV1")
    if not isinstance(graph, MemoryGraphV1):
        raise TypeError("graph must be MemoryGraphV1")
    evidence_items = tuple(evidence)
    redaction_items = tuple(redactions)
    if not all(isinstance(item, MemoryEvidenceV1) for item in evidence_items):
        raise TypeError("evidence must contain only MemoryEvidenceV1 values")
    if not all(isinstance(item, MemoryRedactionV1) for item in redaction_items):
        raise TypeError("redactions must contain only MemoryRedactionV1 values")
    evidence_items = tuple(sorted(evidence_items, key=lambda item: item.id))
    redaction_items = tuple(
        sorted(redaction_items, key=lambda item: (item.path, item.reason))
    )
    return {
        "schema_version": MEMORY_PACK_SCHEMA,
        "manifest": manifest.to_mapping(),
        "graph": graph.to_mapping(),
        "evidence": [item.to_mapping() for item in evidence_items],
        "redactions": [item.to_mapping() for item in redaction_items],
    }


def canonical_memory_pack_json(
    manifest: MemoryPackManifestV1,
    graph: MemoryGraphV1,
    evidence: Sequence[MemoryEvidenceV1] = (),
    redactions: Sequence[MemoryRedactionV1] = (),
) -> str:
    """Return the canonical authoritative preimage used for ``pack_id``."""

    return json.dumps(
        _canonical_payload(manifest, graph, evidence, redactions),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def derive_memory_pack_id(
    manifest: MemoryPackManifestV1,
    graph: MemoryGraphV1,
    evidence: Sequence[MemoryEvidenceV1] = (),
    redactions: Sequence[MemoryRedactionV1] = (),
) -> str:
    canonical = canonical_memory_pack_json(manifest, graph, evidence, redactions)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def issue_memory_pack(
    *,
    manifest: MemoryPackManifestV1,
    graph: MemoryGraphV1,
    evidence: Sequence[MemoryEvidenceV1] = (),
    redactions: Sequence[MemoryRedactionV1] = (),
) -> MemoryPackV1:
    pack_id = derive_memory_pack_id(manifest, graph, evidence, redactions)
    pack = MemoryPackV1(
        pack_id=pack_id,
        manifest=manifest,
        graph=graph,
        evidence=tuple(evidence),
        redactions=tuple(redactions),
    )
    result = verify_memory_pack(pack)
    if not result.passed():
        codes = ", ".join(finding.code for finding in result.findings)
        raise ValueError(f"memory pack cannot be issued: {codes}")
    return pack


def _manifest_from_mapping(payload: Mapping[str, Any]) -> MemoryPackManifestV1:
    _require_exact_fields(payload, expected=MANIFEST_FIELDS, label="manifest")
    return MemoryPackManifestV1(
        project=payload["project"],
        source_repository=payload["source_repository"],
        source_commit=payload["source_commit"],
        created_at=payload["created_at"],
        visibility=payload["visibility"],
        license=payload["license"],
        contains_private_data=payload["contains_private_data"],
        merge_authority=payload["merge_authority"],
        execution_authority=payload["execution_authority"],
        description=payload["description"],
    )


def _node_from_mapping(payload: Mapping[str, Any]) -> MemoryNodeV1:
    _require_exact_fields(payload, expected=NODE_FIELDS, label="node")
    attributes = payload["attributes"]
    if not isinstance(attributes, Mapping):
        raise ValueError("node attributes must be a JSON object")
    return MemoryNodeV1(
        id=payload["id"],
        kind=payload["kind"],
        label=payload["label"],
        status=payload["status"],
        confidence=payload["confidence"],
        attributes=attributes,
    )


def _edge_from_mapping(payload: Mapping[str, Any]) -> MemoryEdgeV1:
    _require_exact_fields(payload, expected=EDGE_FIELDS, label="edge")
    evidence_ids = _require_sequence(payload["evidence_ids"], label="edge evidence_ids")
    return MemoryEdgeV1(
        id=payload["id"],
        source=payload["source"],
        target=payload["target"],
        relation=payload["relation"],
        strength=payload["strength"],
        evidence_ids=tuple(evidence_ids),
    )


def _evidence_from_mapping(payload: Mapping[str, Any]) -> MemoryEvidenceV1:
    _require_exact_fields(payload, expected=EVIDENCE_FIELDS, label="evidence")
    return MemoryEvidenceV1(
        id=payload["id"],
        kind=payload["kind"],
        digest=payload["digest"],
        locator=payload["locator"],
        description=payload["description"],
    )


def _redaction_from_mapping(payload: Mapping[str, Any]) -> MemoryRedactionV1:
    _require_exact_fields(payload, expected=REDACTION_FIELDS, label="redaction")
    return MemoryRedactionV1(path=payload["path"], reason=payload["reason"])


def _graph_from_mapping(payload: Mapping[str, Any]) -> MemoryGraphV1:
    _require_exact_fields(payload, expected=GRAPH_FIELDS, label="graph")
    nodes_payload = _require_sequence(payload["nodes"], label="graph nodes")
    edges_payload = _require_sequence(payload["edges"], label="graph edges")
    selected_path = _require_sequence(
        payload["selected_path"], label="graph selected_path"
    )
    nodes: list[MemoryNodeV1] = []
    for item in nodes_payload:
        if not isinstance(item, Mapping):
            raise ValueError("graph nodes must contain JSON objects")
        nodes.append(_node_from_mapping(item))
    edges: list[MemoryEdgeV1] = []
    for item in edges_payload:
        if not isinstance(item, Mapping):
            raise ValueError("graph edges must contain JSON objects")
        edges.append(_edge_from_mapping(item))
    return MemoryGraphV1(
        nodes=tuple(nodes), edges=tuple(edges), selected_path=tuple(selected_path)
    )


def memory_pack_from_mapping(payload: Mapping[str, Any]) -> MemoryPackV1:
    if not isinstance(payload, Mapping):
        raise TypeError("memory pack must be a JSON object")
    _require_exact_fields(payload, expected=TOP_LEVEL_FIELDS, label="memory pack")

    manifest_payload = payload["manifest"]
    graph_payload = payload["graph"]
    evidence_payload = _require_sequence(payload["evidence"], label="evidence")
    redactions_payload = _require_sequence(payload["redactions"], label="redactions")
    if not isinstance(manifest_payload, Mapping):
        raise ValueError("manifest must be a JSON object")
    if not isinstance(graph_payload, Mapping):
        raise ValueError("graph must be a JSON object")

    evidence: list[MemoryEvidenceV1] = []
    for item in evidence_payload:
        if not isinstance(item, Mapping):
            raise ValueError("evidence must contain JSON objects")
        evidence.append(_evidence_from_mapping(item))
    redactions: list[MemoryRedactionV1] = []
    for item in redactions_payload:
        if not isinstance(item, Mapping):
            raise ValueError("redactions must contain JSON objects")
        redactions.append(_redaction_from_mapping(item))

    return MemoryPackV1(
        schema_version=payload["schema_version"],
        pack_id=payload["pack_id"],
        manifest=_manifest_from_mapping(manifest_payload),
        graph=_graph_from_mapping(graph_payload),
        evidence=tuple(evidence),
        redactions=tuple(redactions),
    )


def load_memory_pack_json(text: str) -> MemoryPackV1:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    try:
        payload = json.loads(text, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError("memory pack is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("memory pack must contain a JSON object")
    return memory_pack_from_mapping(payload)


def verify_memory_pack(pack: MemoryPackV1) -> MemoryPackVerificationResult:
    if not isinstance(pack, MemoryPackV1):
        raise TypeError("pack must be MemoryPackV1")

    expected_id = derive_memory_pack_id(
        pack.manifest, pack.graph, pack.evidence, pack.redactions
    )
    findings: list[MemoryPackFinding] = []
    if pack.pack_id != expected_id:
        findings.append(
            MemoryPackFinding(
                code="CML-MEMORY-PACK-ID-MISMATCH",
                message="pack_id does not match the canonical authoritative preimage",
            )
        )
    if (
        pack.manifest.visibility in {"public", "partner"}
        and pack.manifest.contains_private_data
    ):
        findings.append(
            MemoryPackFinding(
                code="CML-MEMORY-PACK-UNSAFE-SHARING",
                message=(
                    "public and partner memory packs must declare "
                    "contains_private_data=false"
                ),
            )
        )
    if pack.manifest.merge_authority or pack.manifest.execution_authority:
        findings.append(
            MemoryPackFinding(
                code="CML-MEMORY-PACK-AUTHORITY-FORBIDDEN",
                message="memory packs are advisory and must not grant authority",
            )
        )

    findings.sort(key=lambda item: (item.code, item.message))
    return MemoryPackVerificationResult(
        findings=tuple(findings), expected_pack_id=expected_id
    )
