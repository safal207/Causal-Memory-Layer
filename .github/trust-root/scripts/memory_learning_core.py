#!/usr/bin/env python3
"""Pure, stdlib-only construction of proposed post-merge Memory Packs."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

MEMORY_PACK_SCHEMA = "cml-memory-pack-v1"
GENERATED_BRANCH_PREFIX = "cml-learning/"
GENERATED_TITLE_PREFIX = "memory: learn from merged PR #"
GENERATED_ROOT = ".cml/memory/cycles"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
TOKEN = re.compile(r"^[A-Za-z0-9._:/-]+$")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$")
TIMESTAMP_SECONDS = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
)
TIMESTAMP_MILLISECONDS = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)


class LearningLoopError(ValueError):
    """Raised when untrusted merge data cannot form a safe memory proposal."""


def compact_json(value: Any) -> str:
    """Return deterministic compact UTF-8 JSON text."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_json(value: Any) -> str:
    """Hash a deterministic JSON value with SHA-256."""

    return hashlib.sha256(compact_json(value).encode("utf-8")).hexdigest()


def mapping(value: object, *, label: str) -> dict[str, Any]:
    """Require a concrete JSON object."""

    if not isinstance(value, dict):
        raise LearningLoopError(f"{label} must be an object")
    return value


def sequence(value: object, *, label: str) -> list[Any]:
    """Require a concrete JSON array."""

    if not isinstance(value, list):
        raise LearningLoopError(f"{label} must be an array")
    return value


def string(
    value: object, *, label: str, default: str | None = None
) -> str:
    """Require a Unicode-scalar string, optionally applying a null default."""

    if value is None and default is not None:
        return default
    if not isinstance(value, str):
        raise LearningLoopError(f"{label} must be a string")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise LearningLoopError(
            f"{label} must contain only Unicode scalar values"
        )
    return value


def positive_int(value: object, *, label: str) -> int:
    """Require an integer greater than zero."""

    if isinstance(value, bool):
        raise LearningLoopError(f"{label} must be an integer")
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise LearningLoopError(f"{label} must be an integer") from exc
    if parsed < 1:
        raise LearningLoopError(f"{label} must be >= 1")
    return parsed


def full_sha(value: object, *, label: str) -> str:
    """Require a full lowercase 40-character Git SHA."""

    normalized = string(value, label=label).strip().lower()
    if not SHA40.fullmatch(normalized):
        raise LearningLoopError(
            f"{label} must be a full lowercase 40-character SHA"
        )
    return normalized


def timestamp_milliseconds(value: object, *, label: str) -> str:
    """Normalize GitHub UTC timestamps to exact millisecond precision."""

    raw = string(value, label=label)
    if TIMESTAMP_SECONDS.fullmatch(raw):
        normalized = raw[:-1] + ".000Z"
    elif TIMESTAMP_MILLISECONDS.fullmatch(raw):
        normalized = raw
    else:
        raise LearningLoopError(
            f"{label} must be RFC3339 UTC with seconds or millisecond precision"
        )
    try:
        datetime.strptime(normalized, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise LearningLoopError(
            f"{label} must be a real UTC timestamp"
        ) from exc
    return normalized


def truncate(value: str, limit: int = 500) -> str:
    """Normalize whitespace and bound generated display text."""

    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1].rstrip() + "…"


def sections(body: str) -> dict[str, str]:
    """Split a Markdown body into normalized heading sections."""

    result: dict[str, list[str]] = {"preamble": []}
    current = "preamble"
    for line in body.splitlines():
        match = HEADING.match(line)
        if match:
            current = " ".join(match.group(1).strip().lower().split())
            result.setdefault(current, [])
        else:
            result[current].append(line)
    return {
        heading: "\n".join(lines).strip()
        for heading, lines in result.items()
        if "\n".join(lines).strip()
    }


def first_section(
    values: Mapping[str, str], candidates: Iterable[str]
) -> str | None:
    """Return the first section whose heading contains a candidate term."""

    needles = tuple(candidates)
    for heading, value in values.items():
        if any(needle in heading for needle in needles):
            return value
    return None


def normalize_files(values: Sequence[Any]) -> list[dict[str, Any]]:
    """Project GitHub changed files into a deterministic metadata snapshot."""

    result: list[dict[str, Any]] = []
    for raw in values:
        if not isinstance(raw, dict):
            continue
        filename = raw.get("filename")
        if not isinstance(filename, str):
            continue
        result.append(
            {
                "filename": filename,
                "status": raw.get("status")
                if isinstance(raw.get("status"), str)
                else None,
                "additions": raw.get("additions")
                if isinstance(raw.get("additions"), int)
                else 0,
                "deletions": raw.get("deletions")
                if isinstance(raw.get("deletions"), int)
                else 0,
            }
        )
    return sorted(result, key=compact_json)


def normalize_reviews(values: Sequence[Any]) -> list[dict[str, Any]]:
    """Project reviews without carrying review bodies into memory."""

    result: list[dict[str, Any]] = []
    for raw in values:
        if not isinstance(raw, dict):
            continue
        user = raw.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        result.append(
            {
                "id": raw.get("id")
                if isinstance(raw.get("id"), int)
                else None,
                "state": raw.get("state")
                if isinstance(raw.get("state"), str)
                else None,
                "commit_id": raw.get("commit_id")
                if isinstance(raw.get("commit_id"), str)
                else None,
                "user_login": login if isinstance(login, str) else None,
                "submitted_at": raw.get("submitted_at")
                if isinstance(raw.get("submitted_at"), str)
                else None,
            }
        )
    return sorted(result, key=compact_json)


def normalize_checks(values: Sequence[Any]) -> list[dict[str, Any]]:
    """Project complete check-run records into deterministic order."""

    result: list[dict[str, Any]] = []
    for raw in values:
        if not isinstance(raw, dict):
            continue
        result.append(
            {
                "name": string(
                    raw.get("name"), label="check name", default="unknown"
                ),
                "status": string(
                    raw.get("status"), label="check status", default="unknown"
                ),
                "conclusion": raw.get("conclusion")
                if isinstance(raw.get("conclusion"), str)
                else None,
                "details_url": raw.get("details_url")
                if isinstance(raw.get("details_url"), str)
                else None,
            }
        )
    return sorted(result, key=compact_json)


def should_skip(
    pull: Mapping[str, Any], files: Sequence[Mapping[str, Any]]
) -> str | None:
    """Reject generated and memory-only changes to prevent recursion."""

    head = pull.get("head")
    head_ref = head.get("ref") if isinstance(head, dict) else None
    title = pull.get("title")
    if isinstance(head_ref, str) and head_ref.startswith(
        GENERATED_BRANCH_PREFIX
    ):
        return "generated-memory-branch"
    if isinstance(title, str) and title.startswith(GENERATED_TITLE_PREFIX):
        return "generated-memory-title"
    filenames = [item.get("filename") for item in files]
    if filenames and all(
        isinstance(filename, str)
        and filename.startswith(".cml/memory/")
        for filename in filenames
    ):
        return "memory-only-change"
    return None


def node(
    node_id: str,
    kind: str,
    label: str,
    status: str,
    confidence: int,
    attributes: Mapping[str, Any],
) -> dict[str, Any]:
    """Construct a bounded Memory Pack node."""

    if not TOKEN.fullmatch(node_id):
        raise LearningLoopError(f"invalid generated node id: {node_id}")
    return {
        "id": node_id,
        "kind": kind,
        "label": truncate(label),
        "status": status,
        "confidence": confidence,
        "attributes": dict(attributes),
    }


def edge(
    edge_id: str,
    source: str,
    target: str,
    relation: str,
    strength: int,
    evidence_ids: Sequence[str],
) -> dict[str, Any]:
    """Construct a deterministic Memory Pack edge."""

    return {
        "id": edge_id,
        "source": source,
        "target": target,
        "relation": relation,
        "strength": strength,
        "evidence_ids": sorted(set(evidence_ids)),
    }


def evidence(
    evidence_id: str,
    kind: str,
    locator: str,
    description: str,
    snapshot: Any,
) -> dict[str, Any]:
    """Bind a normalized source snapshot into an evidence record."""

    return {
        "id": evidence_id,
        "kind": kind,
        "digest": sha256_json(snapshot),
        "locator": locator,
        "description": truncate(description),
    }


def canonical_preimage(pack: Mapping[str, Any]) -> dict[str, Any]:
    """Return the authoritative Memory Pack preimage excluding pack_id."""

    graph = mapping(pack.get("graph"), label="graph")
    return {
        "schema_version": pack.get("schema_version"),
        "manifest": pack.get("manifest"),
        "graph": {
            "nodes": sorted(
                sequence(graph.get("nodes"), label="nodes"),
                key=lambda item: item["id"],
            ),
            "edges": sorted(
                sequence(graph.get("edges"), label="edges"),
                key=lambda item: item["id"],
            ),
            "selected_path": graph.get("selected_path"),
        },
        "evidence": sorted(
            sequence(pack.get("evidence"), label="evidence"),
            key=lambda item: item["id"],
        ),
        "redactions": sorted(
            sequence(pack.get("redactions"), label="redactions"),
            key=lambda item: (item["path"], item["reason"]),
        ),
    }


def bind_pack_id(pack: dict[str, Any]) -> dict[str, Any]:
    """Compute and attach the deterministic Memory Pack identity."""

    pack["pack_id"] = sha256_json(canonical_preimage(pack))
    return pack


def build_memory_pack(
    *,
    repository: str,
    pull: Mapping[str, Any],
    files: Sequence[Mapping[str, Any]],
    reviews: Sequence[Mapping[str, Any]],
    check_runs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a conservative proposed Memory Pack from merged PR evidence."""

    number = positive_int(pull.get("number"), label="pull request number")
    title = string(pull.get("title"), label="pull request title")
    body = string(pull.get("body"), label="pull request body", default="")
    merged_at = timestamp_milliseconds(pull.get("merged_at"), label="merged_at")
    merge_sha = full_sha(
        pull.get("merge_commit_sha"), label="merge commit SHA"
    )
    head = mapping(pull.get("head"), label="pull request head")
    base = mapping(pull.get("base"), label="pull request base")
    head_sha = full_sha(head.get("sha"), label="pull request head SHA")
    if string(base.get("ref"), label="pull request base ref") != "main":
        raise LearningLoopError(
            "learning loop only accepts pull requests merged into main"
        )
    html_url = string(pull.get("html_url"), label="pull request URL")

    normalized_files = normalize_files(files)
    normalized_reviews = normalize_reviews(reviews)
    normalized_checks = normalize_checks(check_runs)
    parsed = sections(body)
    summary = first_section(parsed, ("summary", "purpose", "goal"))
    cause = first_section(parsed, ("root cause", "problem", "context"))
    design = first_section(
        parsed, ("design", "changes", "implementation", "solution")
    )
    validation = first_section(
        parsed, ("validation", "verification", "testing")
    )
    boundary = first_section(
        parsed, ("boundary", "limitation", "non-claim", "scope")
    )

    evidence_items = [
        evidence(
            "source-pr",
            "document",
            html_url,
            f"Normalized merged pull-request snapshot for #{number}.",
            {
                "repository": repository,
                "number": number,
                "title": title,
                "body": body,
                "head_sha": head_sha,
                "merge_commit_sha": merge_sha,
                "merged_at": merged_at,
            },
        ),
        evidence(
            "source-files",
            "document",
            f"{html_url}/files",
            f"Normalized changed-file snapshot for #{number}.",
            normalized_files,
        ),
        evidence(
            "source-reviews",
            "review",
            f"{html_url}/reviews",
            f"Normalized review snapshot for #{number} without review bodies.",
            normalized_reviews,
        ),
        evidence(
            "source-checks",
            "test",
            f"https://github.com/{repository}/commit/{head_sha}/checks",
            f"Normalized exact-head check-run snapshot for #{number}.",
            normalized_checks,
        ),
        evidence(
            "source-merge",
            "commit",
            f"git:{merge_sha}",
            f"Merge commit for pull request #{number}.",
            {"repository": repository, "merge_commit_sha": merge_sha},
        ),
    ]

    nodes = [
        node(
            "situation-merged-pr",
            "situation",
            summary or title,
            "observed",
            100,
            {"pull_request": number, "source": "explicit-pr-text"},
        )
    ]
    graph_edges: list[dict[str, Any]] = []
    selected_path = ["situation-merged-pr"]
    previous = "situation-merged-pr"

    if cause:
        nodes.append(
            node(
                "cause-explicit",
                "cause",
                cause,
                "observed",
                90,
                {"source": "explicit-pr-section", "inference": False},
            )
        )
        graph_edges.append(
            edge(
                "edge-situation-cause",
                previous,
                "cause-explicit",
                "supports",
                90,
                ("source-pr",),
            )
        )
        previous = "cause-explicit"
        selected_path.append(previous)

    nodes.extend(
        [
            node(
                "action-merged-approach",
                "action",
                design
                or f"Apply the merged approach from PR #{number}: {title}",
                "verified",
                95,
                {
                    "source": "explicit-pr-section"
                    if design
                    else "deterministic-fallback",
                    "changed_files": len(normalized_files),
                    "head_sha": head_sha,
                },
            ),
            node(
                "check-recorded-evidence",
                "check",
                validation
                or (
                    f"Review recorded exact-head checks and reviews for PR "
                    f"#{number} before reuse"
                ),
                "tested",
                90 if normalized_checks else 70,
                {
                    "check_run_count": len(normalized_checks),
                    "review_count": len(normalized_reviews),
                },
            ),
            node(
                "constraint-review-required",
                "constraint",
                boundary
                or (
                    "Human review is required before accepting or sharing "
                    "this generated lesson"
                ),
                "proposed",
                100,
                {
                    "generated": True,
                    "merge_authority": False,
                    "execution_authority": False,
                },
            ),
            node(
                "outcome-merged",
                "outcome",
                f"PR #{number} merged into main as {merge_sha}",
                "verified",
                100,
                {"merge_commit": merge_sha, "merged_at": merged_at},
            ),
            node(
                "lesson-proposed-best-known-path",
                "lesson",
                (
                    f"Best-known repository-local path for PR #{number}: "
                    "reuse the merged approach only when the recorded "
                    "constraints and checks still apply"
                ),
                "proposed",
                75,
                {
                    "generated": True,
                    "human_review_required": True,
                    "globally_optimal": False,
                },
            ),
        ]
    )

    graph_edges.extend(
        [
            edge(
                "edge-to-action",
                previous,
                "action-merged-approach",
                "leads_to",
                90,
                ("source-pr", "source-files"),
            ),
            edge(
                "edge-action-check",
                "action-merged-approach",
                "check-recorded-evidence",
                "requires",
                100,
                ("source-checks", "source-reviews"),
            ),
            edge(
                "edge-check-outcome",
                "check-recorded-evidence",
                "outcome-merged",
                "supports",
                90,
                ("source-checks", "source-reviews", "source-merge"),
            ),
            edge(
                "edge-constraint-lesson",
                "constraint-review-required",
                "lesson-proposed-best-known-path",
                "requires",
                100,
                ("source-pr",),
            ),
            edge(
                "edge-outcome-lesson",
                "outcome-merged",
                "lesson-proposed-best-known-path",
                "leads_to",
                75,
                ("source-merge",),
            ),
        ]
    )
    selected_path.extend(
        [
            "action-merged-approach",
            "check-recorded-evidence",
            "outcome-merged",
            "lesson-proposed-best-known-path",
        ]
    )

    return bind_pack_id(
        {
            "schema_version": MEMORY_PACK_SCHEMA,
            "pack_id": "0" * 64,
            "manifest": {
                "project": repository.split("/", 1)[1],
                "source_repository": f"https://github.com/{repository}",
                "source_commit": merge_sha,
                "created_at": merged_at,
                "visibility": "team",
                "license": "MIT",
                "contains_private_data": True,
                "merge_authority": False,
                "execution_authority": False,
                "description": (
                    f"Automatically proposed decision memory for merged PR "
                    f"#{number}; human review is required before broader sharing."
                ),
            },
            "graph": {
                "nodes": sorted(nodes, key=lambda item: item["id"]),
                "edges": sorted(
                    graph_edges, key=lambda item: item["id"]
                ),
                "selected_path": selected_path,
            },
            "evidence": sorted(
                evidence_items, key=lambda item: item["id"]
            ),
            "redactions": [
                {
                    "path": "review.body",
                    "reason": (
                        "Review bodies are excluded to reduce disclosure and "
                        "prompt-injection carryover."
                    ),
                },
                {
                    "path": "source_event.raw_payload",
                    "reason": "Only normalized source snapshots are retained.",
                },
            ],
        }
    )
