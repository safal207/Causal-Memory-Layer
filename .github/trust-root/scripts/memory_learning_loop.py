#!/usr/bin/env python3
"""Create a reviewable CML Memory Pack proposal after a pull-request merge.

This protected runtime is intentionally stdlib-only. It treats all pull-request,
review, file, and check data as untrusted text and never executes repository
code from the merged change. It writes only to a generated branch and opens a
draft pull request; it never writes directly to the default branch.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

SCHEMA_VERSION = "cml-learning-loop-evidence-v1"
MEMORY_PACK_SCHEMA = "cml-memory-pack-v1"
GENERATED_BRANCH_PREFIX = "cml-learning/"
GENERATED_TITLE_PREFIX = "memory: learn from merged PR #"
GENERATED_ROOT = ".cml/memory/cycles"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TOKEN = re.compile(r"^[A-Za-z0-9._:/-]+$")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$")


class LearningLoopError(ValueError):
    """Raised when a learning-loop proposal cannot be established safely."""


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LearningLoopError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LearningLoopError(f"cannot read JSON object {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise LearningLoopError(f"JSON must contain an object: {path}")
    return payload


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def compact_json(payload: Any) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_json(payload: Any) -> str:
    return hashlib.sha256(compact_json(payload).encode("utf-8")).hexdigest()


def require_repository(value: object) -> str:
    if not isinstance(value, str) or not REPOSITORY.fullmatch(value):
        raise LearningLoopError("repository must use owner/name format")
    return value


def require_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise LearningLoopError(f"{label} must be a string")
    normalized = value.strip().lower()
    if not SHA40.fullmatch(normalized):
        raise LearningLoopError(f"{label} must be a full lowercase 40-character SHA")
    return normalized


def positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool):
        raise LearningLoopError(f"{label} must be an integer")
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise LearningLoopError(f"{label} must be an integer") from exc
    if parsed < 1:
        raise LearningLoopError(f"{label} must be >= 1")
    return parsed


def require_string(value: object, *, label: str, default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str):
        raise LearningLoopError(f"{label} must be a string")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise LearningLoopError(f"{label} must contain only Unicode scalar values")
    return value


def truncate(value: str, limit: int) -> str:
    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1].rstrip() + "…"


def _mapping(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LearningLoopError(f"{label} must be an object")
    return value


def _sequence(value: object, *, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise LearningLoopError(f"{label} must be an array")
    return value


def _section_map(body: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {"preamble": []}
    current = "preamble"
    for raw_line in body.splitlines():
        match = HEADING.match(raw_line)
        if match:
            current = " ".join(match.group(1).strip().lower().split())
            sections.setdefault(current, [])
            continue
        sections[current].append(raw_line)
    return {
        heading: "\n".join(lines).strip()
        for heading, lines in sections.items()
        if "\n".join(lines).strip()
    }


def _first_section(sections: Mapping[str, str], headings: Iterable[str]) -> str | None:
    normalized = tuple(headings)
    for key, value in sections.items():
        if any(candidate in key for candidate in normalized):
            return value
    return None


def _node(
    node_id: str,
    kind: str,
    label: str,
    status: str,
    confidence: int,
    attributes: Mapping[str, Any],
) -> dict[str, Any]:
    if not TOKEN.fullmatch(node_id):
        raise LearningLoopError(f"invalid generated node id: {node_id}")
    return {
        "id": node_id,
        "kind": kind,
        "label": truncate(label, 500),
        "status": status,
        "confidence": confidence,
        "attributes": dict(attributes),
    }


def _edge(
    edge_id: str,
    source: str,
    target: str,
    relation: str,
    strength: int,
    evidence_ids: Sequence[str],
) -> dict[str, Any]:
    return {
        "id": edge_id,
        "source": source,
        "target": target,
        "relation": relation,
        "strength": strength,
        "evidence_ids": sorted(set(evidence_ids)),
    }


def _evidence(
    evidence_id: str,
    kind: str,
    locator: str,
    description: str,
    snapshot: Any,
) -> dict[str, Any]:
    return {
        "id": evidence_id,
        "kind": kind,
        "digest": sha256_json(snapshot),
        "locator": locator,
        "description": truncate(description, 500),
    }


def canonical_memory_pack_preimage(pack: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "pack_id",
        "manifest",
        "graph",
        "evidence",
        "redactions",
    }
    if set(pack) != required:
        raise LearningLoopError("generated memory pack has unexpected top-level fields")
    graph = _mapping(pack["graph"], label="graph")
    nodes = sorted(
        (_mapping(item, label="node") for item in _sequence(graph.get("nodes"), label="nodes")),
        key=lambda item: item.get("id", ""),
    )
    edges = sorted(
        (_mapping(item, label="edge") for item in _sequence(graph.get("edges"), label="edges")),
        key=lambda item: item.get("id", ""),
    )
    evidence = sorted(
        (
            _mapping(item, label="evidence")
            for item in _sequence(pack["evidence"], label="evidence")
        ),
        key=lambda item: item.get("id", ""),
    )
    redactions = sorted(
        (
            _mapping(item, label="redaction")
            for item in _sequence(pack["redactions"], label="redactions")
        ),
        key=lambda item: (item.get("path", ""), item.get("reason", "")),
    )
    return {
        "schema_version": pack["schema_version"],
        "manifest": pack["manifest"],
        "graph": {
            "nodes": nodes,
            "edges": edges,
            "selected_path": graph.get("selected_path"),
        },
        "evidence": evidence,
        "redactions": redactions,
    }


def bind_pack_id(pack: dict[str, Any]) -> dict[str, Any]:
    pack["pack_id"] = sha256_json(canonical_memory_pack_preimage(pack))
    return pack


def _normalized_check_runs(check_runs: Sequence[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for raw in check_runs:
        if not isinstance(raw, dict):
            continue
        normalized.append(
            {
                "name": require_string(raw.get("name"), label="check name", default="unknown"),
                "status": require_string(raw.get("status"), label="check status", default="unknown"),
                "conclusion": raw.get("conclusion")
                if isinstance(raw.get("conclusion"), str)
                else None,
                "details_url": raw.get("details_url")
                if isinstance(raw.get("details_url"), str)
                else None,
            }
        )
    normalized.sort(key=lambda item: (item["name"], item["status"], item["conclusion"] or ""))
    return normalized


def _normalized_reviews(reviews: Sequence[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for raw in reviews:
        if not isinstance(raw, dict):
            continue
        user = raw.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        normalized.append(
            {
                "id": raw.get("id") if isinstance(raw.get("id"), int) else None,
                "state": raw.get("state") if isinstance(raw.get("state"), str) else None,
                "commit_id": raw.get("commit_id")
                if isinstance(raw.get("commit_id"), str)
                else None,
                "user_login": login if isinstance(login, str) else None,
                "submitted_at": raw.get("submitted_at")
                if isinstance(raw.get("submitted_at"), str)
                else None,
            }
        )
    normalized.sort(
        key=lambda item: (
            item["submitted_at"] or "",
            item["user_login"] or "",
            item["id"] or 0,
        )
    )
    return normalized


def _normalized_files(files: Sequence[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for raw in files:
        if not isinstance(raw, dict):
            continue
        filename = raw.get("filename")
        if not isinstance(filename, str):
            continue
        normalized.append(
            {
                "filename": filename,
                "status": raw.get("status") if isinstance(raw.get("status"), str) else None,
                "additions": raw.get("additions") if isinstance(raw.get("additions"), int) else 0,
                "deletions": raw.get("deletions") if isinstance(raw.get("deletions"), int) else 0,
            }
        )
    normalized.sort(key=lambda item: item["filename"])
    return normalized


def should_skip(pull: Mapping[str, Any], files: Sequence[Mapping[str, Any]]) -> str | None:
    head = pull.get("head")
    head_ref = head.get("ref") if isinstance(head, dict) else None
    title = pull.get("title")
    if isinstance(head_ref, str) and head_ref.startswith(GENERATED_BRANCH_PREFIX):
        return "generated-memory-branch"
    if isinstance(title, str) and title.startswith(GENERATED_TITLE_PREFIX):
        return "generated-memory-title"
    filenames = [item.get("filename") for item in files]
    if filenames and all(
        isinstance(filename, str) and filename.startswith(".cml/memory/")
        for filename in filenames
    ):
        return "memory-only-change"
    return None


def build_memory_pack(
    *,
    repository: str,
    pull: Mapping[str, Any],
    files: Sequence[Mapping[str, Any]],
    reviews: Sequence[Mapping[str, Any]],
    check_runs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    number = positive_int(pull.get("number"), label="pull request number")
    title = require_string(pull.get("title"), label="pull request title")
    body = require_string(pull.get("body"), label="pull request body", default="")
    merged_at = require_string(pull.get("merged_at"), label="merged_at")
    merge_sha = require_sha(pull.get("merge_commit_sha"), label="merge commit SHA")
    head = _mapping(pull.get("head"), label="pull request head")
    base = _mapping(pull.get("base"), label="pull request base")
    head_sha = require_sha(head.get("sha"), label="pull request head SHA")
    base_ref = require_string(base.get("ref"), label="pull request base ref")
    if base_ref != "main":
        raise LearningLoopError("learning loop only accepts pull requests merged into main")

    html_url = require_string(pull.get("html_url"), label="pull request URL")
    sections = _section_map(body)
    summary = _first_section(sections, ("summary", "purpose", "goal"))
    root_cause = _first_section(sections, ("root cause", "problem", "context"))
    design = _first_section(sections, ("design", "changes", "implementation", "solution"))
    validation = _first_section(sections, ("validation", "verification", "testing"))
    boundaries = _first_section(sections, ("boundary", "limitation", "non-claim", "scope"))

    file_snapshot = _normalized_files(files)
    review_snapshot = _normalized_reviews(reviews)
    check_snapshot = _normalized_check_runs(check_runs)
    pr_snapshot = {
        "repository": repository,
        "number": number,
        "title": title,
        "body": body,
        "head_sha": head_sha,
        "merge_commit_sha": merge_sha,
        "merged_at": merged_at,
        "base_ref": base_ref,
        "html_url": html_url,
    }

    evidence = [
        _evidence(
            "source-pr",
            "document",
            html_url,
            f"Normalized merged pull-request snapshot for #{number}.",
            pr_snapshot,
        ),
        _evidence(
            "source-files",
            "document",
            f"{html_url}/files",
            f"Normalized changed-file snapshot for #{number}.",
            file_snapshot,
        ),
        _evidence(
            "source-reviews",
            "review",
            f"{html_url}/reviews",
            f"Normalized review snapshot for #{number}.",
            review_snapshot,
        ),
        _evidence(
            "source-checks",
            "test",
            f"https://github.com/{repository}/commit/{head_sha}/checks",
            f"Normalized exact-head check-run snapshot for #{number}.",
            check_snapshot,
        ),
        _evidence(
            "source-merge",
            "commit",
            f"git:{merge_sha}",
            f"Merged commit for pull request #{number}.",
            {"repository": repository, "merge_commit_sha": merge_sha},
        ),
    ]

    situation_label = summary or title
    action_label = design or f"Apply the merged implementation described by PR #{number}: {title}"
    check_label = validation or (
        f"Review the recorded exact-head checks and reviews for PR #{number} before reusing the approach"
    )
    constraint_label = boundaries or (
        "Treat this generated memory as a proposed repository-local lesson; human review is required before acceptance"
    )
    outcome_label = f"PR #{number} merged into main as {merge_sha}"
    lesson_label = (
        f"Best-known repository-local path for the situation described by PR #{number}: "
        "reuse the merged approach only when its recorded constraints and checks still apply"
    )

    nodes = [
        _node(
            "situation-merged-pr",
            "situation",
            situation_label,
            "observed",
            100,
            {"pull_request": number, "source": "explicit-pr-text"},
        )
    ]
    selected_path = ["situation-merged-pr"]
    edges: list[dict[str, Any]] = []
    previous = "situation-merged-pr"

    if root_cause:
        nodes.append(
            _node(
                "cause-explicit",
                "cause",
                root_cause,
                "observed",
                90,
                {"source": "explicit-pr-section", "inference": False},
            )
        )
        edges.append(
            _edge(
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
            _node(
                "action-merged-approach",
                "action",
                action_label,
                "verified",
                95,
                {
                    "source": "explicit-pr-section" if design else "deterministic-fallback",
                    "changed_files": len(file_snapshot),
                    "head_sha": head_sha,
                },
            ),
            _node(
                "check-recorded-evidence",
                "check",
                check_label,
                "tested",
                90 if check_snapshot else 70,
                {
                    "source": "explicit-pr-section" if validation else "recorded-api-snapshot",
                    "check_run_count": len(check_snapshot),
                    "review_count": len(review_snapshot),
                },
            ),
            _node(
                "constraint-review-required",
                "constraint",
                constraint_label,
                "proposed",
                100,
                {
                    "generated": True,
                    "merge_authority": False,
                    "execution_authority": False,
                },
            ),
            _node(
                "outcome-merged",
                "outcome",
                outcome_label,
                "verified",
                100,
                {"merge_commit": merge_sha, "merged_at": merged_at},
            ),
            _node(
                "lesson-proposed-best-known-path",
                "lesson",
                lesson_label,
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

    edges.extend(
        [
            _edge(
                "edge-to-action",
                previous,
                "action-merged-approach",
                "leads_to",
                90,
                ("source-pr", "source-files"),
            ),
            _edge(
                "edge-action-check",
                "action-merged-approach",
                "check-recorded-evidence",
                "requires",
                100,
                ("source-checks", "source-reviews"),
            ),
            _edge(
                "edge-check-outcome",
                "check-recorded-evidence",
                "outcome-merged",
                "supports",
                90,
                ("source-checks", "source-reviews", "source-merge"),
            ),
            _edge(
                "edge-constraint-lesson",
                "constraint-review-required",
                "lesson-proposed-best-known-path",
                "requires",
                100,
                ("source-pr",),
            ),
            _edge(
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

    pack: dict[str, Any] = {
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
                f"Automatically proposed decision memory for merged PR #{number}; "
                "human review is required before broader sharing."
            ),
        },
        "graph": {
            "nodes": sorted(nodes, key=lambda item: item["id"]),
            "edges": sorted(edges, key=lambda item: item["id"]),
            "selected_path": selected_path,
        },
        "evidence": sorted(evidence, key=lambda item: item["id"]),
        "redactions": [
            {
                "path": "source_event.raw_payload",
                "reason": "The generated pack stores normalized snapshots, not the complete GitHub event payload.",
            },
            {
                "path": "review.body",
                "reason": "Review bodies are excluded from automatic memory to reduce accidental disclosure and prompt injection carryover.",
            },
        ],
    }
    return bind_pack_id(pack)


@dataclass
class GitHubApi:
    token: str
    api_url: str = "https://api.github.com"

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        expected: Sequence[int] = (200,),
    ) -> tuple[int, bytes]:
        url = f"{self.api_url}{path}"
        data = None if payload is None else compact_json(payload).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "cml-memory-learning-loop",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=data, method=method, headers=headers)
        try:
            with urlopen(request, timeout=30) as response:
                status = response.status
                body = response.read()
        except HTTPError as exc:
            status = exc.code
            body = exc.read()
        except (URLError, TimeoutError) as exc:
            raise LearningLoopError(f"GitHub API request failed: {method} {path}: {exc}") from exc
        if status not in expected:
            detail = body.decode("utf-8", errors="replace")[:1000]
            raise LearningLoopError(
                f"GitHub API returned {status} for {method} {path}: {detail}"
            )
        return status, body

    def json(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        expected: Sequence[int] = (200,),
    ) -> Any:
        _, body = self._request(method, path, payload=payload, expected=expected)
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"), object_pairs_hook=_unique_json_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LearningLoopError(f"GitHub API returned invalid JSON for {method} {path}") from exc

    def paginated(self, path: str, *, item_key: str | None = None) -> list[Any]:
        items: list[Any] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 11):
            payload = self.json("GET", f"{path}{separator}per_page=100&page={page}")
            page_items = payload.get(item_key) if item_key and isinstance(payload, dict) else payload
            if not isinstance(page_items, list):
                raise LearningLoopError(f"GitHub API pagination payload is invalid: {path}")
            items.extend(page_items)
            if len(page_items) < 100:
                return items
        raise LearningLoopError(f"GitHub API pagination exceeded safe bound: {path}")

    def get_pull(self, repository: str, number: int) -> dict[str, Any]:
        payload = self.json("GET", f"/repos/{repository}/pulls/{number}")
        return _mapping(payload, label="pull request response")

    def list_files(self, repository: str, number: int) -> list[Any]:
        return self.paginated(f"/repos/{repository}/pulls/{number}/files")

    def list_reviews(self, repository: str, number: int) -> list[Any]:
        return self.paginated(f"/repos/{repository}/pulls/{number}/reviews")

    def list_check_runs(self, repository: str, head_sha: str) -> list[Any]:
        return self.paginated(
            f"/repos/{repository}/commits/{head_sha}/check-runs?filter=latest",
            item_key="check_runs",
        )

    def get_ref(self, repository: str, ref: str) -> dict[str, Any] | None:
        encoded = quote(ref, safe="/")
        status, body = self._request(
            "GET",
            f"/repos/{repository}/git/ref/{encoded}",
            expected=(200, 404),
        )
        if status == 404:
            return None
        return _mapping(
            json.loads(body.decode("utf-8"), object_pairs_hook=_unique_json_object),
            label="Git ref response",
        )

    def create_ref(self, repository: str, ref: str, sha: str) -> None:
        self.json(
            "POST",
            f"/repos/{repository}/git/refs",
            payload={"ref": f"refs/heads/{ref}", "sha": sha},
            expected=(201,),
        )

    def get_content(self, repository: str, path: str, ref: str) -> dict[str, Any] | None:
        encoded = quote(path, safe="/")
        status, body = self._request(
            "GET",
            f"/repos/{repository}/contents/{encoded}?ref={quote(ref, safe='')}",
            expected=(200, 404),
        )
        if status == 404:
            return None
        return _mapping(
            json.loads(body.decode("utf-8"), object_pairs_hook=_unique_json_object),
            label="content response",
        )

    def create_content(
        self,
        repository: str,
        *,
        path: str,
        branch: str,
        message: str,
        content: str,
    ) -> None:
        encoded = quote(path, safe="/")
        self.json(
            "PUT",
            f"/repos/{repository}/contents/{encoded}",
            payload={
                "message": message,
                "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
                "branch": branch,
            },
            expected=(201,),
        )

    def find_open_pull(self, repository: str, branch: str) -> dict[str, Any] | None:
        owner = repository.split("/", 1)[0]
        payload = self.json(
            "GET",
            f"/repos/{repository}/pulls?state=open&head={quote(owner + ':' + branch, safe=':')}",
        )
        items = _sequence(payload, label="open pull response")
        if not items:
            return None
        return _mapping(items[0], label="open pull entry")

    def create_pull(
        self,
        repository: str,
        *,
        title: str,
        head: str,
        base: str,
        body: str,
    ) -> dict[str, Any]:
        payload = self.json(
            "POST",
            f"/repos/{repository}/pulls",
            payload={
                "title": title,
                "head": head,
                "base": base,
                "body": body,
                "draft": True,
                "maintainer_can_modify": True,
            },
            expected=(201,),
        )
        return _mapping(payload, label="created pull response")


def propose(
    *,
    api: GitHubApi,
    event: Mapping[str, Any],
    repository: str,
    run_id: int,
    run_attempt: int,
    run_url: str,
) -> dict[str, Any]:
    event_pull = _mapping(event.get("pull_request"), label="event pull request")
    number = positive_int(event_pull.get("number"), label="pull request number")
    pull = api.get_pull(repository, number)
    if pull.get("merged") is not True:
        raise LearningLoopError("pull request is not merged")
    files = _normalized_files(api.list_files(repository, number))
    skip_reason = should_skip(pull, files)

    evidence: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "pull_number": number,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "run_url": run_url,
        "outcome": "NOOP" if skip_reason else "PENDING",
        "skip_reason": skip_reason,
        "memory_path": None,
        "memory_pack_id": None,
        "branch": None,
        "proposal_pull_number": None,
        "proposal_pull_url": None,
        "direct_main_write": False,
        "merge_authority": False,
        "execution_authority": False,
        "passed": True,
    }
    if skip_reason:
        return evidence

    reviews = _normalized_reviews(api.list_reviews(repository, number))
    head = _mapping(pull.get("head"), label="pull request head")
    head_sha = require_sha(head.get("sha"), label="pull request head SHA")
    check_runs = _normalized_check_runs(api.list_check_runs(repository, head_sha))
    pack = build_memory_pack(
        repository=repository,
        pull=pull,
        files=files,
        reviews=reviews,
        check_runs=check_runs,
    )
    merge_sha = require_sha(pull.get("merge_commit_sha"), label="merge commit SHA")
    short_sha = merge_sha[:12]
    memory_path = f"{GENERATED_ROOT}/pr-{number}-{short_sha}.json"
    branch = f"{GENERATED_BRANCH_PREFIX}pr-{number}-{short_sha}"

    existing_main = api.get_content(repository, memory_path, "main")
    if existing_main is not None:
        evidence.update(
            {
                "outcome": "ALREADY_ACCEPTED_NOOP",
                "memory_path": memory_path,
                "memory_pack_id": pack["pack_id"],
            }
        )
        return evidence

    existing_pull = api.find_open_pull(repository, branch)
    if existing_pull is not None:
        evidence.update(
            {
                "outcome": "PROPOSAL_ALREADY_OPEN_NOOP",
                "memory_path": memory_path,
                "memory_pack_id": pack["pack_id"],
                "branch": branch,
                "proposal_pull_number": existing_pull.get("number"),
                "proposal_pull_url": existing_pull.get("html_url"),
            }
        )
        return evidence

    ref = api.get_ref(repository, f"heads/{branch}")
    if ref is None:
        api.create_ref(repository, branch, merge_sha)
    else:
        ref_object = _mapping(ref.get("object"), label="generated branch ref object")
        if ref_object.get("sha") != merge_sha:
            raise LearningLoopError("generated learning branch exists at an unexpected SHA")

    existing_branch_content = api.get_content(repository, memory_path, branch)
    if existing_branch_content is None:
        api.create_content(
            repository,
            path=memory_path,
            branch=branch,
            message=f"memory: learn from merged PR #{number}",
            content=json.dumps(pack, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        )

    title = f"{GENERATED_TITLE_PREFIX}{number}"
    body = (
        f"## Automatic learning proposal\n\n"
        f"This draft PR proposes a reviewable CML Memory Pack derived from merged PR #{number}.\n\n"
        f"- source merge: `{merge_sha}`\n"
        f"- source head: `{head_sha}`\n"
        f"- memory path: `{memory_path}`\n"
        f"- pack ID: `{pack['pack_id']}`\n"
        f"- default visibility: `team`\n"
        f"- merge authority: `false`\n"
        f"- execution authority: `false`\n\n"
        f"The lesson node is generated with `status=proposed` and requires human review. "
        f"Merging this PR accepts the memory into the repository; closing it rejects the proposal.\n\n"
        f"This generated PR is excluded from recursive learning-loop generation."
    )
    proposal_pull = api.create_pull(
        repository,
        title=title,
        head=branch,
        base="main",
        body=body,
    )
    evidence.update(
        {
            "outcome": "PROPOSAL_CREATED",
            "memory_path": memory_path,
            "memory_pack_id": pack["pack_id"],
            "branch": branch,
            "proposal_pull_number": proposal_pull.get("number"),
            "proposal_pull_url": proposal_pull.get("html_url"),
        }
    )
    return evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-path", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    repository = args.repository
    run_id: object = args.run_id
    run_attempt: object = args.run_attempt
    try:
        normalized_repository = require_repository(repository)
        normalized_run_id = positive_int(run_id, label="run id")
        normalized_run_attempt = positive_int(run_attempt, label="run attempt")
        event = read_json_object(args.event_path)
        api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""))
        result = propose(
            api=api,
            event=event,
            repository=normalized_repository,
            run_id=normalized_run_id,
            run_attempt=normalized_run_attempt,
            run_url=args.run_url,
        )
    except Exception as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "repository": repository,
            "pull_number": None,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "run_url": args.run_url,
            "outcome": "LEARNING_LOOP_ERROR",
            "skip_reason": None,
            "memory_path": None,
            "memory_pack_id": None,
            "branch": None,
            "proposal_pull_number": None,
            "proposal_pull_url": None,
            "direct_main_write": False,
            "merge_authority": False,
            "execution_authority": False,
            "passed": False,
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
    write_json(args.output, result)
    if not result.get("passed", False):
        raise SystemExit(
            f"CML memory learning loop failed closed: {result.get('outcome', 'UNKNOWN')}"
        )
    print(
        f"CML memory learning loop outcome={result['outcome']} "
        f"source_pr={result.get('pull_number')} proposal_pr={result.get('proposal_pull_number')}"
    )


if __name__ == "__main__":
    main()
