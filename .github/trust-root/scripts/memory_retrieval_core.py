#!/usr/bin/env python3
"""Pure, deterministic retrieval over accepted CML Memory Packs."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import html
import json
import math
import re
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import quote

import memory_learning_core as learning

SCHEMA_VERSION = "cml-retrieval-evidence-v1"
COMMENT_MARKER = "<!-- cml-retrieval-v0.1 -->"
MEMORY_ROOT = ".cml/memory/cycles"
MAX_RESULTS = 3
MIN_SCORE = 0.05
MAX_BODY_CHARS = 6000
MAX_FILES = 300
MAX_COMMENT_CHARS = 30000
SHA64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
CAMEL_BOUNDARY = re.compile(r"(?<=[a-zа-яіїє])(?=[A-ZА-ЯІЇЄ])")

TOP_FIELDS = {
    "schema_version",
    "pack_id",
    "manifest",
    "graph",
    "evidence",
    "redactions",
}
MANIFEST_FIELDS = {
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
GRAPH_FIELDS = {"nodes", "edges", "selected_path"}
NODE_FIELDS = {"id", "kind", "label", "status", "confidence", "attributes"}
EDGE_FIELDS = {
    "id",
    "source",
    "target",
    "relation",
    "strength",
    "evidence_ids",
}
EVIDENCE_FIELDS = {"id", "kind", "digest", "locator", "description"}
REDACTION_FIELDS = {"path", "reason"}
NODE_WEIGHTS = {
    "situation": 5,
    "cause": 4,
    "constraint": 4,
    "option": 3,
    "action": 5,
    "check": 2,
    "outcome": 3,
    "lesson": 6,
    "evidence": 1,
}
STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "has",
    "have",
    "in",
    "into",
    "is",
    "it",
    "of",
    "on",
    "or",
    "pr",
    "pull",
    "request",
    "that",
    "the",
    "this",
    "to",
    "was",
    "were",
    "with",
    "без",
    "для",
    "его",
    "как",
    "на",
    "не",
    "по",
    "при",
    "это",
    "та",
    "такий",
    "така",
    "таки",
    "що",
    "і",
    "й",
    "в",
    "у",
    "з",
}


class RetrievalError(ValueError):
    """Raised when retrieval input or an accepted Memory Pack is invalid."""


@dataclass(frozen=True)
class MemoryDocument:
    """Validated accepted memory projected into retrieval fields."""

    path: str
    pack_id: str
    source_commit: str
    visibility: str
    contains_private_data: bool
    situation: str
    selected_path: tuple[str, ...]
    constraints: tuple[str, ...]
    token_weights: Mapping[str, int]
    evidence_count: int


@dataclass(frozen=True)
class RetrievalMatch:
    """One deterministic ranked memory result."""

    document: MemoryDocument
    score: float
    matched_terms: tuple[str, ...]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RetrievalError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _mapping(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RetrievalError(f"{label} must be an object")
    return value


def _sequence(value: object, *, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RetrievalError(f"{label} must be an array")
    return value


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise RetrievalError(f"{label} must be a string")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise RetrievalError(f"{label} must contain only Unicode scalar values")
    return value


def _require_fields(
    payload: Mapping[str, Any], *, expected: set[str], label: str
) -> None:
    actual = set(payload)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if unknown:
            details.append(f"unknown={','.join(unknown)}")
        raise RetrievalError(f"invalid {label} fields: {'; '.join(details)}")


def _normalized_identifier_text(value: str) -> str:
    value = CAMEL_BOUNDARY.sub(" ", value)
    return re.sub(r"[/\\._:\-]+", " ", value)


def tokenize(value: str) -> tuple[str, ...]:
    """Tokenize Unicode text deterministically without external models."""

    normalized = _normalized_identifier_text(value).lower()
    tokens: list[str] = []
    for token in TOKEN_RE.findall(normalized):
        if len(token) < 2 or len(token) > 64:
            continue
        if token.isdigit() or token in STOPWORDS:
            continue
        tokens.append(token)
    return tuple(tokens)


def _add_tokens(counter: Counter[str], value: str, weight: int) -> None:
    for token in tokenize(value):
        counter[token] += weight


def build_query_weights(
    *, title: str, body: str, filenames: Sequence[str]
) -> Counter[str]:
    """Build a bounded weighted query from untrusted pull-request metadata."""

    result: Counter[str] = Counter()
    _add_tokens(result, title[:1000], 4)
    _add_tokens(result, body[:MAX_BODY_CHARS], 1)
    for filename in filenames[:MAX_FILES]:
        _add_tokens(result, filename[:512], 3)
    return result


def _canonical_preimage(pack: Mapping[str, Any]) -> dict[str, Any]:
    graph = _mapping(pack.get("graph"), label="graph")
    return {
        "schema_version": pack.get("schema_version"),
        "manifest": pack.get("manifest"),
        "graph": {
            "nodes": sorted(
                _sequence(graph.get("nodes"), label="nodes"),
                key=lambda item: item["id"],
            ),
            "edges": sorted(
                _sequence(graph.get("edges"), label="edges"),
                key=lambda item: item["id"],
            ),
            "selected_path": graph.get("selected_path"),
        },
        "evidence": sorted(
            _sequence(pack.get("evidence"), label="evidence"),
            key=lambda item: item["id"],
        ),
        "redactions": sorted(
            _sequence(pack.get("redactions"), label="redactions"),
            key=lambda item: (item["path"], item["reason"]),
        ),
    }


def _validate_schema(pack: Mapping[str, Any]) -> None:
    _require_fields(pack, expected=TOP_FIELDS, label="top-level")
    if pack.get("schema_version") != learning.MEMORY_PACK_SCHEMA:
        raise RetrievalError("unexpected Memory Pack schema version")
    manifest = _mapping(pack.get("manifest"), label="manifest")
    graph = _mapping(pack.get("graph"), label="graph")
    _require_fields(manifest, expected=MANIFEST_FIELDS, label="manifest")
    _require_fields(graph, expected=GRAPH_FIELDS, label="graph")
    for raw in _sequence(graph.get("nodes"), label="nodes"):
        _require_fields(
            _mapping(raw, label="node"), expected=NODE_FIELDS, label="node"
        )
    for raw in _sequence(graph.get("edges"), label="edges"):
        _require_fields(
            _mapping(raw, label="edge"), expected=EDGE_FIELDS, label="edge"
        )
    for raw in _sequence(pack.get("evidence"), label="evidence"):
        _require_fields(
            _mapping(raw, label="evidence item"),
            expected=EVIDENCE_FIELDS,
            label="evidence",
        )
    for raw in _sequence(pack.get("redactions"), label="redactions"):
        _require_fields(
            _mapping(raw, label="redaction"),
            expected=REDACTION_FIELDS,
            label="redaction",
        )


def parse_memory_pack(
    text: str, *, path: str, repository: str
) -> MemoryDocument:
    """Strictly validate and project one accepted Memory Pack."""

    if not path.startswith(f"{MEMORY_ROOT}/") or not path.endswith(".json"):
        raise RetrievalError("memory path is outside the accepted root")
    try:
        payload = json.loads(text, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise RetrievalError(f"invalid JSON in {path}") from exc
    pack = _mapping(payload, label="Memory Pack")
    _validate_schema(pack)

    pack_id = _string(pack.get("pack_id"), label="pack_id")
    if not SHA64.fullmatch(pack_id):
        raise RetrievalError("pack_id must be a lowercase SHA-256 digest")
    expected_id = learning.sha256_json(_canonical_preimage(pack))
    if expected_id != pack_id:
        raise RetrievalError("Memory Pack identity mismatch")

    manifest = _mapping(pack.get("manifest"), label="manifest")
    if manifest.get("source_repository") != f"https://github.com/{repository}":
        raise RetrievalError("Memory Pack repository binding mismatch")
    source_commit = learning.full_sha(
        manifest.get("source_commit"), label="source commit"
    )
    visibility = _string(manifest.get("visibility"), label="visibility")
    if visibility not in {"private", "team", "partner", "public"}:
        raise RetrievalError("unsupported Memory Pack visibility")
    contains_private_data = manifest.get("contains_private_data")
    if not isinstance(contains_private_data, bool):
        raise RetrievalError("contains_private_data must be boolean")
    if manifest.get("merge_authority") is not False:
        raise RetrievalError("Memory Pack must not grant merge authority")
    if manifest.get("execution_authority") is not False:
        raise RetrievalError("Memory Pack must not grant execution authority")

    graph = _mapping(pack.get("graph"), label="graph")
    raw_nodes = _sequence(graph.get("nodes"), label="nodes")
    raw_edges = _sequence(graph.get("edges"), label="edges")
    selected_ids = _sequence(graph.get("selected_path"), label="selected_path")
    if not selected_ids or len(selected_ids) != len(set(selected_ids)):
        raise RetrievalError("selected_path must be non-empty without duplicates")

    nodes: dict[str, dict[str, Any]] = {}
    token_weights: Counter[str] = Counter()
    constraints: list[str] = []
    for raw in raw_nodes:
        node = _mapping(raw, label="node")
        node_id = _string(node.get("id"), label="node id")
        if node_id in nodes:
            raise RetrievalError(f"duplicate node id: {node_id}")
        kind = _string(node.get("kind"), label="node kind")
        label = _string(node.get("label"), label="node label")
        nodes[node_id] = node
        _add_tokens(token_weights, label, NODE_WEIGHTS.get(kind, 1))
        if kind == "constraint":
            constraints.append(label)

    evidence_ids: set[str] = set()
    evidence_items = _sequence(pack.get("evidence"), label="evidence")
    for raw in evidence_items:
        item = _mapping(raw, label="evidence item")
        evidence_id = _string(item.get("id"), label="evidence id")
        if evidence_id in evidence_ids:
            raise RetrievalError(f"duplicate evidence id: {evidence_id}")
        evidence_ids.add(evidence_id)
        _add_tokens(
            token_weights,
            _string(item.get("description"), label="evidence description"),
            1,
        )

    edge_pairs: set[tuple[str, str]] = set()
    edge_ids: set[str] = set()
    for raw in raw_edges:
        edge = _mapping(raw, label="edge")
        edge_id = _string(edge.get("id"), label="edge id")
        if edge_id in edge_ids:
            raise RetrievalError(f"duplicate edge id: {edge_id}")
        edge_ids.add(edge_id)
        source = _string(edge.get("source"), label="edge source")
        target = _string(edge.get("target"), label="edge target")
        if source == target or source not in nodes or target not in nodes:
            raise RetrievalError("edge must connect distinct existing nodes")
        edge_pairs.add((source, target))
        for evidence_id in _sequence(
            edge.get("evidence_ids"), label="edge evidence_ids"
        ):
            if evidence_id not in evidence_ids:
                raise RetrievalError("edge references missing evidence")

    selected_labels: list[str] = []
    for index, raw_id in enumerate(selected_ids):
        node_id = _string(raw_id, label="selected_path node id")
        if node_id not in nodes:
            raise RetrievalError("selected_path references missing node")
        selected_labels.append(_string(nodes[node_id]["label"], label="node label"))
        _add_tokens(token_weights, selected_labels[-1], 2)
        if index and (selected_ids[index - 1], node_id) not in edge_pairs:
            raise RetrievalError("selected_path has no directed connecting edge")
    if nodes[selected_ids[0]].get("kind") != "situation":
        raise RetrievalError("selected_path must start with a situation")
    if nodes[selected_ids[-1]].get("kind") not in {"outcome", "lesson"}:
        raise RetrievalError("selected_path must end with an outcome or lesson")

    _add_tokens(
        token_weights,
        _string(manifest.get("description"), label="manifest description"),
        2,
    )
    situation = selected_labels[0]
    return MemoryDocument(
        path=path,
        pack_id=pack_id,
        source_commit=source_commit,
        visibility=visibility,
        contains_private_data=contains_private_data,
        situation=situation,
        selected_path=tuple(selected_labels),
        constraints=tuple(constraints),
        token_weights=dict(sorted(token_weights.items())),
        evidence_count=len(evidence_items),
    )


def is_publishable(document: MemoryDocument, *, repository_visibility: str) -> bool:
    """Apply conservative repository/comment visibility rules."""

    if repository_visibility == "private":
        return True
    if repository_visibility == "internal":
        return (
            document.visibility in {"team", "partner", "public"}
            and not document.contains_private_data
        )
    return document.visibility == "public" and not document.contains_private_data


def _idf(documents: Sequence[MemoryDocument]) -> dict[str, float]:
    document_frequency: Counter[str] = Counter()
    for document in documents:
        document_frequency.update(document.token_weights.keys())
    total = len(documents)
    return {
        token: math.log((total + 1) / (frequency + 1)) + 1.0
        for token, frequency in document_frequency.items()
    }


def retrieve(
    query_weights: Mapping[str, int],
    documents: Sequence[MemoryDocument],
    *,
    limit: int = MAX_RESULTS,
) -> tuple[RetrievalMatch, ...]:
    """Rank memories with deterministic TF-IDF cosine similarity."""

    if limit < 1 or limit > MAX_RESULTS:
        raise RetrievalError(f"limit must be between 1 and {MAX_RESULTS}")
    if not query_weights or not documents:
        return ()
    idf = _idf(documents)
    query_vector = {
        token: (1.0 + math.log(weight)) * idf.get(token, 1.0)
        for token, weight in query_weights.items()
        if weight > 0
    }
    query_norm = math.sqrt(sum(value * value for value in query_vector.values()))
    if query_norm == 0:
        return ()

    ranked: list[RetrievalMatch] = []
    for document in documents:
        doc_vector = {
            token: (1.0 + math.log(weight)) * idf.get(token, 1.0)
            for token, weight in document.token_weights.items()
            if weight > 0
        }
        matched = sorted(set(query_vector) & set(doc_vector))
        if len(matched) < 2:
            continue
        dot = sum(query_vector[token] * doc_vector[token] for token in matched)
        doc_norm = math.sqrt(sum(value * value for value in doc_vector.values()))
        if doc_norm == 0:
            continue
        score = dot / (query_norm * doc_norm)
        if score < MIN_SCORE:
            continue
        contributions = sorted(
            matched,
            key=lambda token: (
                -(query_vector[token] * doc_vector[token]),
                token,
            ),
        )
        ranked.append(
            RetrievalMatch(
                document=document,
                score=round(score, 6),
                matched_terms=tuple(contributions[:6]),
            )
        )
    ranked.sort(
        key=lambda item: (
            -item.score,
            -len(item.matched_terms),
            item.document.pack_id,
            item.document.path,
        )
    )
    return tuple(ranked[:limit])


def _safe_text(value: str, *, limit: int = 500) -> str:
    normalized = " ".join(value.replace(COMMENT_MARKER, "").split())
    if len(normalized) > limit:
        normalized = normalized[: limit - 1].rstrip() + "…"
    normalized = normalized.replace("`", "'")
    return html.escape(normalized, quote=False)


def _path_url(repository: str, base_sha: str, path: str) -> str:
    return f"https://github.com/{repository}/blob/{base_sha}/{quote(path, safe='/')}"


def render_comment(
    *,
    repository: str,
    repository_visibility: str,
    pull_number: int,
    head_sha: str,
    base_sha: str,
    matches: Sequence[RetrievalMatch],
    accepted_count: int,
    withheld_count: int,
    rejected_count: int,
) -> str:
    """Render one bounded managed GitHub comment."""

    lines = [
        COMMENT_MARKER,
        "## Relevant CML Memory",
        "",
        (
            f"Deterministic retrieval for PR #{pull_number} at head "
            f"`{head_sha[:12]}` against accepted memory on base `{base_sha[:12]}`."
        ),
        "",
    ]
    if matches:
        for index, match in enumerate(matches, start=1):
            document = match.document
            path_text = " → ".join(
                _safe_text(label, limit=220) for label in document.selected_path
            )
            lines.extend(
                [
                    f"### {index}. {_safe_text(document.situation, limit=240)}",
                    "",
                    f"**Why it matched:** {', '.join(f'`{term}`' for term in match.matched_terms)}",
                    "",
                    f"**Best-known path:** {path_text}",
                    "",
                ]
            )
            if document.constraints:
                constraints = "; ".join(
                    _safe_text(value, limit=220)
                    for value in document.constraints[:3]
                )
                lines.extend([f"**Constraints:** {constraints}", ""])
            lines.extend(
                [
                    (
                        f"**Evidence:** [Memory Pack]({_path_url(repository, base_sha, document.path)}) "
                        f"· source `{document.source_commit}` · pack `{document.pack_id}` "
                        f"· {document.evidence_count} evidence records"
                    ),
                    "",
                    f"**Relevance:** `{match.score:.6f}`",
                    "",
                ]
            )
    else:
        lines.extend(
            [
                "### No publishable accepted memory matched this change",
                "",
                "The retrieval engine found no accepted pack that passed both relevance and privacy rules.",
                "",
            ]
        )

    if repository_visibility == "public":
        privacy_text = (
            "Public-repository policy surfaces only packs with `visibility=public` "
            "and `contains_private_data=false`."
        )
    else:
        privacy_text = "Repository-local privacy policy was applied before ranking."
    lines.extend(
        [
            "---",
            (
                f"Accepted candidates: **{accepted_count}** · withheld by privacy: "
                f"**{withheld_count}** · rejected as invalid: **{rejected_count}**."
            ),
            privacy_text,
            "",
            (
                "CML memory is advisory: verify that the recorded constraints still apply. "
                "This comment grants no approval, execution, or merge authority."
            ),
        ]
    )
    result = "\n".join(lines)
    if len(result) > MAX_COMMENT_CHARS:
        raise RetrievalError("rendered retrieval comment exceeds the safe bound")
    return result
