#!/usr/bin/env python3
"""Fail-safe review issue for repositories that block Actions-created PRs."""

from __future__ import annotations

import json
from typing import Any, Mapping

import memory_learning_core as core
import memory_learning_github as github

PR_CREATION_BLOCKED = (
    "GitHub Actions is not permitted to create or approve pull requests."
)
FALLBACK_TITLE_PREFIX = "memory proposal blocked for merged PR #"


def _is_exact_pr_creation_block(exc: BaseException, repository: str) -> bool:
    message = str(exc)
    return (
        isinstance(exc, core.LearningLoopError)
        and f"POST /repos/{repository}/pulls" in message
        and "GitHub API returned 403" in message
        and PR_CREATION_BLOCKED in message
    )


def _render_pack(pack: Mapping[str, Any]) -> str:
    return json.dumps(
        pack, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"


def _expected_proposal(
    api: github.GitHubApi,
    *,
    repository: str,
    pull_number: int,
) -> tuple[str, str, str, str, str]:
    pull = api.pull(repository, pull_number)
    if pull.get("merged") is not True:
        raise core.LearningLoopError("pull request is not merged")
    source_files = api.files(repository, pull_number)
    if core.should_skip(pull, core.normalize_files(source_files)):
        raise core.LearningLoopError(
            "blocked-PR fallback cannot be created for an excluded merge"
        )
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
    branch = f"{core.GENERATED_BRANCH_PREFIX}pr-{pull_number}-{short_sha}"
    memory_path = (
        f"{core.GENERATED_ROOT}/pr-{pull_number}-{short_sha}.json"
    )
    rendered = _render_pack(pack)

    if api.content(repository, memory_path, "main") is not None:
        raise core.LearningLoopError(
            "blocked-PR fallback found memory already accepted on main"
        )
    branch_ref = api.ref(repository, branch)
    if branch_ref is None:
        raise core.LearningLoopError(
            "blocked-PR fallback cannot find the generated branch"
        )
    branch_content = api.content(repository, memory_path, branch)
    if branch_content is None or api.content_text(branch_content) != rendered:
        raise core.LearningLoopError(
            "blocked-PR fallback cannot authenticate the exact generated pack"
        )
    return branch, memory_path, pack["pack_id"], head_sha, merge_sha


def _find_existing_issue(
    api: github.GitHubApi,
    *,
    repository: str,
    title: str,
) -> dict[str, Any] | None:
    for raw in api.paginated(f"/repos/{repository}/issues?state=all"):
        if not isinstance(raw, dict) or "pull_request" in raw:
            continue
        if raw.get("title") == title:
            return raw
    return None


def _create_or_get_issue(
    api: github.GitHubApi,
    *,
    repository: str,
    pull_number: int,
    branch: str,
    memory_path: str,
    pack_id: str,
    head_sha: str,
    merge_sha: str,
) -> dict[str, Any]:
    title = f"{FALLBACK_TITLE_PREFIX}{pull_number}"
    existing = _find_existing_issue(
        api, repository=repository, title=title
    )
    if existing is not None:
        return existing
    payload = api.json(
        "POST",
        f"/repos/{repository}/issues",
        payload={
            "title": title,
            "body": (
                "## Automatic Memory Learning fallback\n\n"
                "The protected Learning Loop generated and authenticated the "
                "Memory Pack branch, but GitHub repository settings blocked the "
                "final draft pull-request creation call.\n\n"
                f"- source PR: #{pull_number}\n"
                f"- source head: `{head_sha}`\n"
                f"- source merge: `{merge_sha}`\n"
                f"- generated branch: `{branch}`\n"
                f"- memory path: `{memory_path}`\n"
                f"- pack ID: `{pack_id}`\n"
                "- direct main write: `false`\n"
                "- merge authority: `false`\n"
                "- execution authority: `false`\n\n"
                "Enable **Allow GitHub Actions to create and approve pull "
                "requests** in repository Actions settings, then re-run the "
                "Learning Loop. Until then, this issue is the review surface "
                "for the exact generated branch."
            ),
        },
        expected=(201,),
    )
    return core.mapping(payload, label="fallback issue response")


def propose_with_fallback(
    *,
    api: github.GitHubApi,
    repository: str,
    pull_number: int,
    run_id: int,
    run_attempt: int,
    run_url: str,
) -> dict[str, Any]:
    """Run normal proposal creation, recovering only the exact Actions 403."""

    try:
        return github.propose(
            api=api,
            repository=repository,
            pull_number=pull_number,
            run_id=run_id,
            run_attempt=run_attempt,
            run_url=run_url,
        )
    except core.LearningLoopError as exc:
        if not _is_exact_pr_creation_block(exc, repository):
            raise

    existing_proposal = api.proposal(
        repository,
        f"{core.GENERATED_BRANCH_PREFIX}pr-{pull_number}-",
    )
    if existing_proposal is not None:
        return github.propose(
            api=api,
            repository=repository,
            pull_number=pull_number,
            run_id=run_id,
            run_attempt=run_attempt,
            run_url=run_url,
        )

    branch, memory_path, pack_id, head_sha, merge_sha = _expected_proposal(
        api, repository=repository, pull_number=pull_number
    )
    issue = _create_or_get_issue(
        api,
        repository=repository,
        pull_number=pull_number,
        branch=branch,
        memory_path=memory_path,
        pack_id=pack_id,
        head_sha=head_sha,
        merge_sha=merge_sha,
    )
    result = github.evidence_template(
        repository=repository,
        number=pull_number,
        run_id=run_id,
        run_attempt=run_attempt,
        run_url=run_url,
    )
    result.update(
        {
            "outcome": "PROPOSAL_BRANCH_CREATED_PR_BLOCKED",
            "branch": branch,
            "memory_path": memory_path,
            "memory_pack_id": pack_id,
            "fallback_issue_number": issue.get("number"),
            "fallback_issue_url": issue.get("html_url"),
            "validation_dispatched": False,
        }
    )
    return result
