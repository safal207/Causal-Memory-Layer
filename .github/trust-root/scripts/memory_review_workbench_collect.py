#!/usr/bin/env python3
"""Collect read-only live context for Human Review Workbench v0.5.

The collector consumes frozen Semantic Acceptance v0.4 packets. It does not
recompute or override their machine verdicts. It enriches each packet with the
actual generated lesson/situation/action and a net current-main comparison for
every source-PR changed path.

Path comparison is source-merge state vs current-main state. It is not evidence
that a path was never changed and reverted between those revisions.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from cml.experimental.memory_proposal_review_workbench import (
    CONTEXT_SCHEMA,
    PATH_DIVERGED,
    PATH_MISSING,
    PATH_SAME,
)
from cml.experimental.memory_proposal_semantic_acceptance import (
    INTAKE_SCHEMA,
    SemanticAcceptanceError,
    verify_semantic_acceptance_intake,
)

API = "https://api.github.com"
BLOB_REF_RE = re.compile(r"/blob/([0-9a-f]{40})/(.+)$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class WorkbenchCollectionError(RuntimeError):
    pass


def _repository(value: Any) -> str:
    if not isinstance(value, str) or not REPOSITORY_RE.fullmatch(value.strip()):
        raise WorkbenchCollectionError("repository must be owner/name")
    return value.strip()


def _sha40(value: Any, field: str) -> str:
    text = _text(value, field)
    if not SHA40_RE.fullmatch(text):
        raise WorkbenchCollectionError(f"{field} must be a 40-char lowercase hex SHA")
    return text


class GitHubReader:
    def __init__(self, token: str) -> None:
        if not token:
            raise WorkbenchCollectionError("GITHUB_TOKEN is required")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "cml-human-review-workbench-v0.5",
        }

    def get(self, path: str, *, allow_404: bool = False) -> Any:
        if path.startswith("https://") and not path.startswith(API + "/"):
            raise WorkbenchCollectionError("GitHub API URL must remain on api.github.com")
        url = path if path.startswith("https://") else API + path
        request = Request(url, headers=self._headers)
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code == 404 and allow_404:
                return None
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            raise WorkbenchCollectionError(
                f"GitHub API {exc.code} for {url}: {detail}"
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise WorkbenchCollectionError(
                f"GitHub API transport failure for {url}: {exc}"
            ) from exc

    def paginate_list(self, path: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        page = 1
        separator = "&" if "?" in path else "?"
        while True:
            payload = self.get(f"{path}{separator}per_page=100&page={page}")
            if not isinstance(payload, list):
                raise WorkbenchCollectionError(f"expected list response for {path}")
            rows = [item for item in payload if isinstance(item, dict)]
            result.extend(rows)
            if len(payload) < 100:
                return result
            page += 1


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkbenchCollectionError(f"{field} must be an object")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkbenchCollectionError(f"{field} must be a non-empty string")
    return value.strip()


def _pack_ref(packet: Mapping[str, Any], repository: str) -> tuple[str, str, str]:
    refs = packet.get("gate_evidence_refs")
    if not isinstance(refs, list):
        raise WorkbenchCollectionError("packet gate_evidence_refs must be a list")
    prefix = f"https://github.com/{repository}/blob/"
    candidates = [ref for ref in refs if isinstance(ref, str) and ref.startswith(prefix)]
    if len(candidates) != 1:
        raise WorkbenchCollectionError(
            "packet must contain exactly one repository Memory Pack blob reference"
        )
    match = BLOB_REF_RE.search(candidates[0])
    if match is None:
        raise WorkbenchCollectionError("Memory Pack blob reference is malformed")
    return candidates[0], match.group(1), match.group(2)


def _contents(
    reader: GitHubReader,
    repository: str,
    path: str,
    ref: str,
    *,
    allow_missing: bool = False,
) -> Mapping[str, Any] | None:
    encoded_path = quote(path, safe="/")
    encoded_ref = quote(ref, safe="")
    payload = reader.get(
        f"/repos/{repository}/contents/{encoded_path}?ref={encoded_ref}",
        allow_404=allow_missing,
    )
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise WorkbenchCollectionError(f"contents response for {path} must be an object")
    return payload


def _memory_pack(
    reader: GitHubReader, repository: str, ref: str, path: str
) -> Mapping[str, Any]:
    payload = _contents(reader, repository, path, ref)
    assert payload is not None
    if payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
        raise WorkbenchCollectionError("Memory Pack contents must be base64")
    try:
        decoded = base64.b64decode(payload["content"]).decode("utf-8")
        pack = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkbenchCollectionError("Memory Pack is not valid UTF-8 JSON") from exc
    return _mapping(pack, "Memory Pack")


def _selected_node(pack: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    graph = _mapping(pack.get("graph"), "Memory Pack graph")
    nodes_raw = graph.get("nodes")
    selected_raw = graph.get("selected_path")
    if not isinstance(nodes_raw, list) or not isinstance(selected_raw, list):
        raise WorkbenchCollectionError("Memory Pack graph nodes/selected_path are required")
    selected = {item for item in selected_raw if isinstance(item, str)}
    matches = [
        node
        for node in nodes_raw
        if isinstance(node, Mapping)
        and node.get("kind") == kind
        and node.get("id") in selected
    ]
    if len(matches) != 1:
        raise WorkbenchCollectionError(
            f"Memory Pack selected_path must contain exactly one {kind} node"
        )
    return matches[0]


def _state_token(payload: Mapping[str, Any] | None) -> str | None:
    if payload is None:
        return None
    sha = payload.get("sha")
    if not isinstance(sha, str) or not sha:
        raise WorkbenchCollectionError("contents response missing blob SHA")
    return sha


def _path_states(
    reader: GitHubReader,
    repository: str,
    source_pr: int,
    source_merge: str,
    current_main: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    files = reader.paginate_list(f"/repos/{repository}/pulls/{source_pr}/files")
    if not files:
        raise WorkbenchCollectionError(f"source PR #{source_pr} has no changed files")

    states: list[dict[str, Any]] = []
    refs: list[str] = []
    seen: set[str] = set()
    for item in files:
        path = _text(item.get("filename"), f"source PR #{source_pr} filename")
        if path in seen:
            raise WorkbenchCollectionError(f"source PR #{source_pr} duplicate filename")
        seen.add(path)
        status = _text(item.get("status"), f"source PR #{source_pr} file status")

        if status == "removed":
            source_token = "ABSENT"
            source_payload = None
        else:
            source_payload = _contents(reader, repository, path, source_merge)
            if source_payload is None:
                raise WorkbenchCollectionError(
                    f"source PR #{source_pr} path missing at source merge: {path}"
                )
            source_token = _state_token(source_payload)
            assert source_token is not None

        current_payload = _contents(
            reader,
            repository,
            path,
            current_main,
            allow_missing=True,
        )
        current_token = _state_token(current_payload)

        if source_token == "ABSENT":
            if current_token is None:
                state = PATH_SAME
                current_token = "ABSENT"
            else:
                state = PATH_DIVERGED
        elif current_token is None:
            state = PATH_MISSING
        elif current_token == source_token:
            state = PATH_SAME
        else:
            state = PATH_DIVERGED

        states.append(
            {
                "path": path,
                "status": state,
                "source_blob_sha": source_token,
                "current_blob_sha": current_token,
                "source_pr_file_status": status,
                "previous_filename": item.get("previous_filename"),
            }
        )
        refs.append(
            f"https://github.com/{repository}/blob/{source_merge}/{path}"
            if source_token != "ABSENT"
            else f"https://github.com/{repository}/pull/{source_pr}/files"
        )
        if current_token is not None and current_token != "ABSENT":
            refs.append(f"https://github.com/{repository}/blob/{current_main}/{path}")

    return states, sorted(set(refs))


def _validate_context_coverage(
    contexts: list[dict[str, Any]], expected_count: int
) -> None:
    if len(contexts) != expected_count:
        raise WorkbenchCollectionError("review context coverage is incomplete")
    for key in ("packet_id", "decision_id", "pack_id", "proposal_pr", "source_pr"):
        if len({item[key] for item in contexts}) != len(contexts):
            raise WorkbenchCollectionError(
                f"review context coverage has duplicate {key}"
            )


def collect(
    intake: Mapping[str, Any], repository: str, token: str
) -> dict[str, Any]:
    repository = _repository(repository)
    intake = _mapping(intake, "intake")
    if intake.get("schema") != INTAKE_SCHEMA:
        raise WorkbenchCollectionError(f"intake.schema must be {INTAKE_SCHEMA}")
    try:
        verified_intake_digest = verify_semantic_acceptance_intake(intake)
    except SemanticAcceptanceError as exc:
        raise WorkbenchCollectionError(f"frozen semantic intake is invalid: {exc}") from exc
    current_main = _sha40(
        intake.get("current_main_revision"), "intake.current_main_revision"
    )
    intake_digest = _text(intake.get("intake_digest"), "intake.intake_digest")
    if intake_digest != verified_intake_digest:
        raise WorkbenchCollectionError("verified intake digest mismatch")
    packets = intake.get("packets")
    if not isinstance(packets, list) or not packets:
        raise WorkbenchCollectionError("intake.packets must be a non-empty list")

    reader = GitHubReader(token)
    contexts: list[dict[str, Any]] = []
    for raw in packets:
        packet = _mapping(raw, "packet")
        packet_id = _text(packet.get("packet_id"), "packet.packet_id")
        decision_id = _text(packet.get("decision_id"), "packet.decision_id")
        pack_id = _text(packet.get("pack_id"), "packet.pack_id")
        proposal_pr = packet.get("proposal_pr")
        source_pr = packet.get("source_pr")
        source_merge = _sha40(packet.get("source_merge"), "packet.source_merge")
        if isinstance(proposal_pr, bool) or not isinstance(proposal_pr, int) or proposal_pr <= 0:
            raise WorkbenchCollectionError("packet.proposal_pr must be positive")
        if isinstance(source_pr, bool) or not isinstance(source_pr, int) or source_pr <= 0:
            raise WorkbenchCollectionError("packet.source_pr must be positive")
        if packet.get("current_main_revision") != current_main:
            raise WorkbenchCollectionError(
                f"proposal #{proposal_pr} packet is stale against intake main"
            )

        pack_url, pack_ref, pack_path = _pack_ref(packet, repository)
        pack = _memory_pack(reader, repository, pack_ref, pack_path)
        if pack.get("pack_id") != pack_id:
            raise WorkbenchCollectionError(
                f"proposal #{proposal_pr} Memory Pack identity mismatch"
            )
        manifest = _mapping(pack.get("manifest"), "Memory Pack manifest")
        if manifest.get("source_commit") != source_merge:
            raise WorkbenchCollectionError(
                f"proposal #{proposal_pr} Memory Pack source commit mismatch"
            )

        situation = _selected_node(pack, "situation")
        action = _selected_node(pack, "action")
        lesson = _selected_node(pack, "lesson")
        lesson_confidence = lesson.get("confidence")
        if (
            isinstance(lesson_confidence, bool)
            or not isinstance(lesson_confidence, int)
            or not 0 <= lesson_confidence <= 100
        ):
            raise WorkbenchCollectionError("lesson confidence must be an integer in [0, 100]")

        source_pull = reader.get(f"/repos/{repository}/pulls/{source_pr}")
        source_pull = _mapping(source_pull, f"source PR #{source_pr}")
        source_title = _text(source_pull.get("title"), f"source PR #{source_pr} title")
        if source_pull.get("merge_commit_sha") != source_merge:
            raise WorkbenchCollectionError(
                f"source PR #{source_pr} merge SHA changed or is misbound"
            )

        states, path_refs = _path_states(
            reader,
            repository,
            source_pr,
            source_merge,
            current_main,
        )
        context_refs = sorted(
            set(
                [
                    pack_url,
                    f"https://github.com/{repository}/pull/{source_pr}",
                    f"https://github.com/{repository}/commit/{source_merge}",
                    f"https://github.com/{repository}/commit/{current_main}",
                    *path_refs,
                ]
            )
        )
        contexts.append(
            {
                "packet_id": packet_id,
                "decision_id": decision_id,
                "proposal_pr": proposal_pr,
                "source_pr": source_pr,
                "pack_id": pack_id,
                "current_main_revision": current_main,
                "source_title": source_title,
                "situation_label": _text(situation.get("label"), "situation.label"),
                "action_label": _text(action.get("label"), "action.label"),
                "lesson_label": _text(lesson.get("label"), "lesson.label"),
                "lesson_confidence": lesson_confidence,
                "pack_created_at": _text(
                    manifest.get("created_at"), "Memory Pack manifest.created_at"
                ),
                "path_states": states,
                "context_evidence_refs": context_refs,
            }
        )

    _validate_context_coverage(contexts, len(packets))
    return {
        "schema": CONTEXT_SCHEMA,
        "source_intake_digest": intake_digest,
        "current_main_revision": current_main,
        "context_count": len(contexts),
        "contexts": sorted(contexts, key=lambda item: item["proposal_pr"]),
        "non_claims": [
            "path comparison is net source-merge versus current-main state",
            "a matching blob does not prove the path was never modified and reverted",
            "path divergence does not prove semantic invalidity",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect Human Review Workbench v0.5 context")
    parser.add_argument("intake", type=Path)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        repository = _repository(args.repository)
    except WorkbenchCollectionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        intake = json.loads(args.intake.read_text(encoding="utf-8"))
        result = collect(intake, repository, os.environ.get(args.token_env, ""))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    except (OSError, json.JSONDecodeError, WorkbenchCollectionError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps({"context_count": result["context_count"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
