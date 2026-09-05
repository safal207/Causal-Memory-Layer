#!/usr/bin/env python3
"""Protected GitHub adapter for the post-merge CML learning loop."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import memory_learning_core as core

VALIDATION_WORKFLOWS = (
    "ci.yml",
    "python-package-validation.yml",
    "security.yml",
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise core.LearningLoopError(f"duplicate JSON key: {key}")
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
            data = core.compact_json(payload).encode("utf-8")
        request = Request(
            f"{self.api_url}{path}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "cml-memory-learning-loop",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                status, body = response.status, response.read()
        except HTTPError as exc:
            status, body = exc.code, exc.read()
        except (URLError, TimeoutError) as exc:
            raise core.LearningLoopError(
                f"GitHub API request failed: {method} {path}: {exc}"
            ) from exc
        if status not in expected:
            detail = body.decode("utf-8", errors="replace")[:1000]
            raise core.LearningLoopError(
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
            raise core.LearningLoopError(
                f"GitHub API returned invalid JSON for {method} {path}"
            ) from exc

    def paginated(self, path: str, *, item_key: str | None = None) -> list[Any]:
        items: list[Any] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 11):
            payload = self.json(
                "GET", f"{path}{separator}per_page=100&page={page}"
            )
            page_items = (
                payload.get(item_key)
                if item_key and isinstance(payload, dict)
                else payload
            )
            if not isinstance(page_items, list):
                raise core.LearningLoopError(
                    f"invalid paginated response: {path}"
                )
            items.extend(page_items)
            if len(page_items) < 100:
                return items
        raise core.LearningLoopError(f"pagination exceeded safe bound: {path}")

    def pull(self, repository: str, number: int) -> dict[str, Any]:
        return core.mapping(
            self.json("GET", f"/repos/{repository}/pulls/{number}"),
            label="pull request response",
        )

    def files(self, repository: str, number: int) -> list[Any]:
        return self.paginated(f"/repos/{repository}/pulls/{number}/files")

    def reviews(self, repository: str, number: int) -> list[Any]:
        return self.paginated(f"/repos/{repository}/pulls/{number}/reviews")

    def checks(self, repository: str, sha: str) -> list[Any]:
        return self.paginated(
            f"/repos/{repository}/commits/{sha}/check-runs?filter=latest",
            item_key="check_runs",
        )

    def ref(self, repository: str, branch: str) -> dict[str, Any] | None:
        status, body = self.request(
            "GET",
            f"/repos/{repository}/git/ref/heads/{quote(branch, safe='/')}",
            expected=(200, 404),
        )
        if status == 404:
            return None
        return core.mapping(
            json.loads(
                body.decode("utf-8"), object_pairs_hook=_unique_object
            ),
            label="ref response",
        )

    def create_ref(self, repository: str, branch: str, sha: str) -> None:
        self.json(
            "POST",
            f"/repos/{repository}/git/refs",
            payload={"ref": f"refs/heads/{branch}", "sha": sha},
            expected=(201,),
        )

    def content(
        self, repository: str, path: str, ref: str
    ) -> dict[str, Any] | None:
        status, body = self.request(
            "GET",
            f"/repos/{repository}/contents/{quote(path, safe='/')}"
            f"?ref={quote(ref, safe='')}",
            expected=(200, 404),
        )
        if status == 404:
            return None
        return core.mapping(
            json.loads(
                body.decode("utf-8"), object_pairs_hook=_unique_object
            ),
            label="content response",
        )

    def content_text(self, payload: Mapping[str, Any]) -> str:
        encoded = payload.get("content")
        if not isinstance(encoded, str) or payload.get("encoding") != "base64":
            raise core.LearningLoopError(
                "existing generated content is not base64"
            )
        normalized = "".join(encoded.split())
        try:
            return base64.b64decode(normalized, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise core.LearningLoopError(
                "existing generated content is invalid"
            ) from exc

    def create_content(
        self,
        repository: str,
        *,
        path: str,
        branch: str,
        message: str,
        text: str,
    ) -> None:
        self.json(
            "PUT",
            f"/repos/{repository}/contents/{quote(path, safe='/')}",
            payload={
                "message": message,
                "branch": branch,
                "content": base64.b64encode(text.encode("utf-8")).decode(
                    "ascii"
                ),
            },
            expected=(201,),
        )

    def proposal(
        self, repository: str, branch: str
    ) -> dict[str, Any] | None:
        owner = repository.split("/", 1)[0]
        payload = self.json(
            "GET",
            f"/repos/{repository}/pulls?state=all&head="
            f"{quote(owner + ':' + branch, safe=':')}",
        )
        values = [
            core.mapping(item, label="proposal")
            for item in core.sequence(payload, label="proposal response")
        ]
        if not values:
            return None
        return next(
            (item for item in values if item.get("state") == "open"),
            values[0],
        )

    def create_pull(
        self,
        repository: str,
        *,
        title: str,
        branch: str,
        body: str,
    ) -> dict[str, Any]:
        return core.mapping(
            self.json(
                "POST",
                f"/repos/{repository}/pulls",
                payload={
                    "title": title,
                    "head": branch,
                    "base": "main",
                    "body": body,
                    "draft": True,
                    "maintainer_can_modify": True,
                },
                expected=(201,),
            ),
            label="created pull response",
        )

    def dispatch_validation(self, repository: str, branch: str) -> None:
        for workflow in VALIDATION_WORKFLOWS:
            self.request(
                "POST",
                f"/repos/{repository}/actions/workflows/{workflow}/dispatches",
                payload={"ref": branch},
                expected=(204,),
            )


def evidence_template(
    *,
    repository: str,
    number: int,
    run_id: int,
    run_attempt: int,
    run_url: str,
) -> dict[str, Any]:
    return {
        "schema_version": "cml-learning-loop-evidence-v1",
        "repository": repository,
        "pull_number": number,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "run_url": run_url,
        "outcome": "PENDING",
        "skip_reason": None,
        "memory_path": None,
        "memory_pack_id": None,
        "branch": None,
        "proposal_pull_number": None,
        "proposal_pull_url": None,
        "validation_workflows": list(VALIDATION_WORKFLOWS),
        "validation_dispatched": False,
        "direct_main_write": False,
        "merge_authority": False,
        "execution_authority": False,
        "passed": True,
    }


def _render_pack(pack: Mapping[str, Any]) -> str:
    return json.dumps(
        pack, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"


def _verify_open_proposal(
    api: GitHubApi,
    *,
    repository: str,
    proposal: Mapping[str, Any],
    branch: str,
    memory_path: str,
    rendered: str,
) -> int:
    proposal_number = core.positive_int(
        proposal.get("number"), label="proposal pull number"
    )
    proposal_content = api.content(repository, memory_path, branch)
    if (
        proposal_content is None
        or api.content_text(proposal_content) != rendered
    ):
        raise core.LearningLoopError(
            "open generated proposal does not contain the exact expected memory pack"
        )
    proposal_files = core.normalize_files(
        api.files(repository, proposal_number)
    )
    if [item["filename"] for item in proposal_files] != [memory_path]:
        raise core.LearningLoopError(
            "open generated proposal contains unexpected changed files"
        )
    return proposal_number


def propose(
    *,
    api: GitHubApi,
    repository: str,
    pull_number: int,
    run_id: int,
    run_attempt: int,
    run_url: str,
) -> dict[str, Any]:
    pull = api.pull(repository, pull_number)
    if pull.get("merged") is not True:
        raise core.LearningLoopError("pull request is not merged")

    source_files = api.files(repository, pull_number)
    normalized_files = core.normalize_files(source_files)
    result = evidence_template(
        repository=repository,
        number=pull_number,
        run_id=run_id,
        run_attempt=run_attempt,
        run_url=run_url,
    )
    skip_reason = core.should_skip(pull, normalized_files)
    if skip_reason:
        result.update({"outcome": "NOOP", "skip_reason": skip_reason})
        return result

    head = core.mapping(pull.get("head"), label="pull request head")
    head_sha = core.full_sha(
        head.get("sha"), label="pull request head SHA"
    )
    pack = core.build_memory_pack(
        repository=repository,
        pull=pull,
        files=source_files,
        reviews=api.reviews(repository, pull_number),
        check_runs=api.checks(repository, head_sha),
    )
    merge_sha = core.full_sha(
        pull.get("merge_commit_sha"), label="merge commit SHA"
    )
    short_sha = merge_sha[:12]
    memory_path = (
        f"{core.GENERATED_ROOT}/pr-{pull_number}-{short_sha}.json"
    )
    branch = f"{core.GENERATED_BRANCH_PREFIX}pr-{pull_number}-{short_sha}"
    rendered = _render_pack(pack)
    result.update(
        {
            "memory_path": memory_path,
            "memory_pack_id": pack["pack_id"],
            "branch": branch,
        }
    )

    if api.content(repository, memory_path, "main") is not None:
        result["outcome"] = "ALREADY_ACCEPTED_NOOP"
        return result

    existing_proposal = api.proposal(repository, branch)
    if existing_proposal is not None:
        state = existing_proposal.get("state")
        proposal_number = core.positive_int(
            existing_proposal.get("number"), label="proposal pull number"
        )
        result.update(
            {
                "outcome": "PROPOSAL_ALREADY_OPEN_NOOP"
                if state == "open"
                else "PROPOSAL_CLOSED_NOOP",
                "proposal_pull_number": proposal_number,
                "proposal_pull_url": existing_proposal.get("html_url"),
            }
        )
        if state == "open":
            _verify_open_proposal(
                api,
                repository=repository,
                proposal=existing_proposal,
                branch=branch,
                memory_path=memory_path,
                rendered=rendered,
            )
            api.dispatch_validation(repository, branch)
            result["validation_dispatched"] = True
        return result

    branch_ref = api.ref(repository, branch)
    branch_content = (
        api.content(repository, memory_path, branch) if branch_ref else None
    )
    if branch_ref is None:
        api.create_ref(repository, branch, merge_sha)
    elif branch_content is None:
        ref_object = core.mapping(
            branch_ref.get("object"), label="branch ref object"
        )
        if ref_object.get("sha") != merge_sha:
            raise core.LearningLoopError(
                "generated branch exists at an unexpected commit without "
                "the expected pack"
            )
    elif api.content_text(branch_content) != rendered:
        raise core.LearningLoopError(
            "generated branch contains a different memory proposal"
        )

    if branch_content is None:
        api.create_content(
            repository,
            path=memory_path,
            branch=branch,
            message=f"memory: learn from merged PR #{pull_number}",
            text=rendered,
        )

    proposal = api.create_pull(
        repository,
        title=f"{core.GENERATED_TITLE_PREFIX}{pull_number}",
        branch=branch,
        body=(
            "## Automatic learning proposal\n\n"
            f"Reviewable Memory Pack derived from merged PR #{pull_number}.\n\n"
            f"- source merge: `{merge_sha}`\n"
            f"- source head: `{head_sha}`\n"
            f"- memory path: `{memory_path}`\n"
            f"- pack ID: `{pack['pack_id']}`\n"
            "- default visibility: `team`\n"
            "- contains private data: `true`\n"
            "- merge authority: `false`\n"
            "- execution authority: `false`\n\n"
            "The generated lesson has `status=proposed`. Merging this draft "
            "accepts the memory; closing it rejects the proposal. This PR is "
            "excluded from recursion."
        ),
    )
    api.dispatch_validation(repository, branch)
    result.update(
        {
            "outcome": "PROPOSAL_CREATED",
            "proposal_pull_number": proposal.get("number"),
            "proposal_pull_url": proposal.get("html_url"),
            "validation_dispatched": True,
        }
    )
    return result
