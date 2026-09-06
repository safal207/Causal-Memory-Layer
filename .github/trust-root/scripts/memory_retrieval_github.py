#!/usr/bin/env python3
"""Protected GitHub adapter for CML Retrieval v0.1."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import memory_retrieval_core as core

BOT_LOGIN = "github-actions[bot]"
MAX_MEMORY_FILES = 500
MAX_FILE_BYTES = 1_000_000


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise core.RetrievalError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


@dataclass
class GitHubApi:
    token: str
    api_url: str = "https://api.github.com"

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        expected: Sequence[int] = (200,),
    ) -> tuple[int, bytes]:
        data = None
        if payload is not None:
            data = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        request = Request(
            f"{self.api_url}{path}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "cml-memory-retrieval",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                status, body = response.status, response.read()
        except HTTPError as exc:
            status, body = exc.code, exc.read()
        except (URLError, TimeoutError) as exc:
            raise core.RetrievalError(
                f"GitHub API request failed: {method} {path}: {exc}"
            ) from exc
        if status not in expected:
            detail = body.decode("utf-8", errors="replace")[:1000]
            raise core.RetrievalError(
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
        _, body = self.request(method, path, payload=payload, expected=expected)
        if not body:
            return None
        try:
            return json.loads(
                body.decode("utf-8"), object_pairs_hook=_unique_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise core.RetrievalError(
                f"GitHub API returned invalid JSON for {method} {path}"
            ) from exc

    def paginated(self, path: str) -> list[Any]:
        items: list[Any] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 11):
            payload = self.json(
                "GET", f"{path}{separator}per_page=100&page={page}"
            )
            if not isinstance(payload, list):
                raise core.RetrievalError(f"invalid paginated response: {path}")
            items.extend(payload)
            if len(payload) < 100:
                return items
        raise core.RetrievalError(f"pagination exceeded safe bound: {path}")

    def pull(self, repository: str, number: int) -> dict[str, Any]:
        payload = self.json("GET", f"/repos/{repository}/pulls/{number}")
        if not isinstance(payload, dict):
            raise core.RetrievalError("pull request response must be an object")
        return payload

    def files(self, repository: str, number: int) -> list[Any]:
        return self.paginated(f"/repos/{repository}/pulls/{number}/files")

    def repository(self, repository: str) -> dict[str, Any]:
        payload = self.json("GET", f"/repos/{repository}")
        if not isinstance(payload, dict):
            raise core.RetrievalError("repository response must be an object")
        return payload

    def directory(self, repository: str, path: str, ref: str) -> list[Any]:
        status, body = self.request(
            "GET",
            f"/repos/{repository}/contents/{quote(path, safe='/')}"
            f"?ref={quote(ref, safe='')}",
            expected=(200, 404),
        )
        if status == 404:
            return []
        try:
            payload = json.loads(
                body.decode("utf-8"), object_pairs_hook=_unique_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise core.RetrievalError("invalid memory directory response") from exc
        if not isinstance(payload, list):
            raise core.RetrievalError("memory root must be a directory")
        if len(payload) > MAX_MEMORY_FILES:
            raise core.RetrievalError("memory root exceeds the safe file bound")
        return payload

    def content(
        self, repository: str, path: str, ref: str
    ) -> dict[str, Any]:
        payload = self.json(
            "GET",
            f"/repos/{repository}/contents/{quote(path, safe='/')}"
            f"?ref={quote(ref, safe='')}",
        )
        if not isinstance(payload, dict):
            raise core.RetrievalError("content response must be an object")
        return payload

    def content_text(self, payload: Mapping[str, Any]) -> str:
        encoded = payload.get("content")
        if payload.get("encoding") != "base64" or not isinstance(encoded, str):
            raise core.RetrievalError("memory content must use base64 encoding")
        size = payload.get("size")
        if isinstance(size, int) and size > MAX_FILE_BYTES:
            raise core.RetrievalError("memory file exceeds the safe size bound")
        try:
            raw = base64.b64decode("".join(encoded.split()), validate=True)
            if len(raw) > MAX_FILE_BYTES:
                raise core.RetrievalError("memory file exceeds the safe size bound")
            return raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise core.RetrievalError("memory content is not valid UTF-8 base64") from exc

    def comments(self, repository: str, number: int) -> list[Any]:
        return self.paginated(f"/repos/{repository}/issues/{number}/comments")

    def create_comment(
        self, repository: str, number: int, body: str
    ) -> dict[str, Any]:
        payload = self.json(
            "POST",
            f"/repos/{repository}/issues/{number}/comments",
            payload={"body": body},
            expected=(201,),
        )
        if not isinstance(payload, dict):
            raise core.RetrievalError("created comment response must be an object")
        return payload

    def update_comment(
        self, repository: str, comment_id: int, body: str
    ) -> dict[str, Any]:
        payload = self.json(
            "PATCH",
            f"/repos/{repository}/issues/comments/{comment_id}",
            payload={"body": body},
        )
        if not isinstance(payload, dict):
            raise core.RetrievalError("updated comment response must be an object")
        return payload


def _positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool):
        raise core.RetrievalError(f"{label} must be an integer")
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise core.RetrievalError(f"{label} must be an integer") from exc
    if parsed < 1:
        raise core.RetrievalError(f"{label} must be positive")
    return parsed


def _string(value: object, *, label: str, default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str):
        raise core.RetrievalError(f"{label} must be a string")
    return value


def _skip_reason(pull: Mapping[str, Any], filenames: Sequence[str]) -> str | None:
    head = pull.get("head")
    head_ref = head.get("ref") if isinstance(head, dict) else None
    title = pull.get("title")
    if isinstance(head_ref, str) and head_ref.startswith("cml-learning/"):
        return "generated-memory-branch"
    if isinstance(title, str) and title.startswith("memory: learn from merged PR #"):
        return "generated-memory-title"
    if filenames and all(
        filename.startswith(f"{core.MEMORY_ROOT}/") for filename in filenames
    ):
        return "memory-only-change"
    return None


def _load_documents(
    api: GitHubApi,
    *,
    repository: str,
    base_sha: str,
    repository_visibility: str,
) -> tuple[list[core.MemoryDocument], int, int, list[str]]:
    entries = api.directory(repository, core.MEMORY_ROOT, base_sha)
    accepted: list[core.MemoryDocument] = []
    publishable: list[core.MemoryDocument] = []
    rejected: list[str] = []
    paths: list[str] = []
    for raw in entries:
        if not isinstance(raw, dict):
            rejected.append("non-object directory entry")
            continue
        path = raw.get("path")
        if (
            raw.get("type") != "file"
            or not isinstance(path, str)
            or not path.startswith(f"{core.MEMORY_ROOT}/")
            or not path.endswith(".json")
        ):
            continue
        paths.append(path)
    for path in sorted(set(paths)):
        try:
            document = core.parse_memory_pack(
                api.content_text(api.content(repository, path, base_sha)),
                path=path,
                repository=repository,
            )
        except Exception as exc:
            rejected.append(f"{path}: {type(exc).__name__}: {str(exc)[:200]}")
            continue
        accepted.append(document)
        if core.is_publishable(
            document, repository_visibility=repository_visibility
        ):
            publishable.append(document)
    withheld_count = len(accepted) - len(publishable)
    return publishable, len(accepted), withheld_count, rejected


def _managed_comment(
    api: GitHubApi,
    *,
    repository: str,
    pull_number: int,
    body: str,
) -> tuple[str, int, int]:
    managed: list[dict[str, Any]] = []
    for raw in api.comments(repository, pull_number):
        if not isinstance(raw, dict):
            continue
        user = raw.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        comment_body = raw.get("body")
        if (
            login == BOT_LOGIN
            and isinstance(comment_body, str)
            and core.COMMENT_MARKER in comment_body
        ):
            managed.append(raw)
    managed.sort(key=lambda item: item.get("id", 0))
    if managed:
        comment_id = _positive_int(managed[0].get("id"), label="comment id")
        response = api.update_comment(repository, comment_id, body)
        returned_id = _positive_int(response.get("id"), label="comment id")
        return "updated", returned_id, len(managed) - 1
    response = api.create_comment(repository, pull_number, body)
    return (
        "created",
        _positive_int(response.get("id"), label="comment id"),
        0,
    )


def retrieve_for_pull(
    *,
    api: GitHubApi,
    repository: str,
    pull_number: int,
    run_id: int,
    run_attempt: int,
    run_url: str,
) -> dict[str, Any]:
    """Retrieve accepted memories and create or update one managed comment."""

    pull = api.pull(repository, pull_number)
    if pull.get("state") != "open":
        raise core.RetrievalError("retrieval only accepts open pull requests")
    head = pull.get("head")
    base = pull.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        raise core.RetrievalError("pull request refs must be objects")
    head_sha = _string(head.get("sha"), label="head SHA").lower()
    base_sha = _string(base.get("sha"), label="base SHA").lower()
    if not re_full_sha(head_sha) or not re_full_sha(base_sha):
        raise core.RetrievalError("pull request refs must be full lowercase SHAs")
    if _string(base.get("ref"), label="base ref") != "main":
        raise core.RetrievalError("retrieval only accepts pull requests targeting main")

    raw_files = api.files(repository, pull_number)
    filenames = sorted(
        {
            raw["filename"]
            for raw in raw_files
            if isinstance(raw, dict) and isinstance(raw.get("filename"), str)
        }
    )
    skip_reason = _skip_reason(pull, filenames)
    result: dict[str, Any] = {
        "schema_version": core.SCHEMA_VERSION,
        "repository": repository,
        "pull_number": pull_number,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "run_url": run_url,
        "outcome": "SKIPPED" if skip_reason else "PENDING",
        "skip_reason": skip_reason,
        "accepted_count": 0,
        "publishable_count": 0,
        "withheld_count": 0,
        "rejected_count": 0,
        "selected": [],
        "comment_action": None,
        "comment_id": None,
        "duplicate_managed_comments": 0,
        "direct_main_write": False,
        "approval_authority": False,
        "merge_authority": False,
        "execution_authority": False,
        "passed": True,
    }
    if skip_reason:
        return result

    repository_payload = api.repository(repository)
    repository_visibility = _string(
        repository_payload.get("visibility"),
        label="repository visibility",
        default="unknown",
    )
    documents, accepted_count, withheld_count, rejected = _load_documents(
        api,
        repository=repository,
        base_sha=base_sha,
        repository_visibility=repository_visibility,
    )
    query = core.build_query_weights(
        title=_string(pull.get("title"), label="pull title"),
        body=_string(pull.get("body"), label="pull body", default=""),
        filenames=filenames,
    )
    matches = core.retrieve(query, documents)
    body = core.render_comment(
        repository=repository,
        repository_visibility=repository_visibility,
        pull_number=pull_number,
        head_sha=head_sha,
        base_sha=base_sha,
        matches=matches,
        accepted_count=accepted_count,
        withheld_count=withheld_count,
        rejected_count=len(rejected),
    )
    comment_action, comment_id, duplicate_count = _managed_comment(
        api,
        repository=repository,
        pull_number=pull_number,
        body=body,
    )
    result.update(
        {
            "outcome": "COMMENT_UPSERTED",
            "accepted_count": accepted_count,
            "publishable_count": len(documents),
            "withheld_count": withheld_count,
            "rejected_count": len(rejected),
            "rejected": rejected[:20],
            "selected": [
                {
                    "path": match.document.path,
                    "pack_id": match.document.pack_id,
                    "source_commit": match.document.source_commit,
                    "score": match.score,
                    "matched_terms": list(match.matched_terms),
                }
                for match in matches
            ],
            "comment_action": comment_action,
            "comment_id": comment_id,
            "duplicate_managed_comments": duplicate_count,
        }
    )
    return result


def re_full_sha(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value)
