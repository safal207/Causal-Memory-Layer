#!/usr/bin/env python3
"""Hardened GitHub orchestration for CML Retrieval v0.1.1."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

import memory_retrieval_core as core
import memory_retrieval_github as legacy


class RetrievalHardeningError(core.RetrievalError):
    """Raised when privacy or managed-comment reconciliation fails closed."""


def _managed_comments(
    api: Any, repository: str, pull_number: int
) -> list[dict[str, Any]]:
    managed: list[dict[str, Any]] = []
    for raw in api.comments(repository, pull_number):
        if not isinstance(raw, dict):
            continue
        user = raw.get("user")
        login = user.get("login") if isinstance(user, dict) else None
        body = raw.get("body")
        if (
            login == legacy.BOT_LOGIN
            and isinstance(body, str)
            and core.COMMENT_MARKER in body
        ):
            managed.append(raw)
    managed.sort(key=lambda item: item.get("id", 0))
    return managed


def _comment_id(comment: Mapping[str, Any]) -> int:
    return legacy._positive_int(comment.get("id"), label="comment id")


def _delete_comment(api: Any, repository: str, comment_id: int) -> None:
    delete = getattr(api, "delete_comment", None)
    if callable(delete):
        delete(repository, comment_id)
        return
    request = getattr(api, "request", None)
    if not callable(request):
        raise RetrievalHardeningError(
            "GitHub adapter cannot delete duplicate managed comments"
        )
    request(
        "DELETE",
        f"/repos/{repository}/issues/comments/{comment_id}",
        expected=(204,),
    )


def reconcile_managed_comment(
    api: Any,
    *,
    repository: str,
    pull_number: int,
    body: str,
) -> tuple[str, int, int]:
    """Upsert and verify exactly one bot-authored managed comment."""

    initial = _managed_comments(api, repository, pull_number)
    created_id: int | None = None
    if initial:
        canonical_id = _comment_id(initial[0])
        api.update_comment(repository, canonical_id, body)
        action = "updated"
    else:
        response = api.create_comment(repository, pull_number, body)
        created_id = _comment_id(response)
        canonical_id = created_id
        action = "created"

    observed = _managed_comments(api, repository, pull_number)
    if not observed:
        raise RetrievalHardeningError(
            "managed comment disappeared after create or update"
        )

    canonical = observed[0]
    canonical_id = _comment_id(canonical)
    if canonical.get("body") != body:
        api.update_comment(repository, canonical_id, body)

    duplicates = observed[1:]
    for duplicate in duplicates:
        _delete_comment(api, repository, _comment_id(duplicate))

    final = _managed_comments(api, repository, pull_number)
    if len(final) != 1:
        raise RetrievalHardeningError(
            "managed comment reconciliation did not leave exactly one comment"
        )
    final_id = _comment_id(final[0])
    if final_id != canonical_id or final[0].get("body") != body:
        raise RetrievalHardeningError(
            "managed comment reconciliation produced an unexpected canonical comment"
        )
    if created_id is not None and final_id != created_id:
        action = "created-and-reconciled"
    return action, final_id, len(duplicates)


def render_privacy_safe_comment(
    *,
    repository: str,
    repository_visibility: str,
    pull_number: int,
    head_sha: str,
    base_sha: str,
    matches: Sequence[core.RetrievalMatch],
    accepted_count: int,
    withheld_count: int,
    rejected_count: int,
) -> str:
    """Render legacy content while removing non-public corpus metadata."""

    rendered = core.render_comment(
        repository=repository,
        repository_visibility=repository_visibility,
        pull_number=pull_number,
        head_sha=head_sha,
        base_sha=base_sha,
        matches=matches,
        accepted_count=accepted_count,
        withheld_count=withheld_count,
        rejected_count=rejected_count,
    )
    if repository_visibility == "private":
        return rendered

    publishable_count = max(0, accepted_count - withheld_count)
    safe_lines: list[str] = []
    for line in rendered.splitlines():
        if line.startswith("Accepted candidates:"):
            safe_lines.append(
                f"Publishable candidates evaluated: **{publishable_count}** "
                f"· selected: **{len(matches)}**."
            )
            continue
        if line == (
            "The retrieval engine found no accepted pack that passed both "
            "relevance and privacy rules."
        ):
            safe_lines.append(
                "No publishable accepted memory met the relevance threshold."
            )
            continue
        safe_lines.append(line)
    result = "\n".join(safe_lines)
    forbidden = (
        "withheld by privacy",
        "rejected as invalid",
        "Accepted candidates:",
    )
    if any(fragment in result for fragment in forbidden):
        raise RetrievalHardeningError(
            "public retrieval comment retained sensitive corpus metadata"
        )
    return result


def _base_result(
    *,
    repository: str,
    pull_number: int,
    head_sha: str,
    base_sha: str,
    run_id: int,
    run_attempt: int,
    run_url: str,
    skip_reason: str | None,
) -> dict[str, Any]:
    return {
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
        "rejected": [],
        "privacy_summary_redacted": False,
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


def _redact_non_private_evidence(result: dict[str, Any]) -> None:
    result["accepted_count"] = None
    result["withheld_count"] = None
    result["rejected_count"] = None
    result["rejected"] = []
    result["privacy_summary_redacted"] = True


def retrieve_for_pull(
    *,
    api: Any,
    repository: str,
    pull_number: int,
    run_id: int,
    run_attempt: int,
    run_url: str,
) -> dict[str, Any]:
    """Retrieve accepted memory with privacy-safe evidence and exact-one comment."""

    pull = api.pull(repository, pull_number)
    if pull.get("state") != "open":
        raise RetrievalHardeningError(
            "retrieval only accepts open pull requests"
        )
    head = pull.get("head")
    base = pull.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        raise RetrievalHardeningError("pull request refs must be objects")
    head_sha = legacy._string(head.get("sha"), label="head SHA").lower()
    base_sha = legacy._string(base.get("sha"), label="base SHA").lower()
    if not legacy.re_full_sha(head_sha) or not legacy.re_full_sha(base_sha):
        raise RetrievalHardeningError(
            "pull request refs must be full lowercase SHAs"
        )
    if legacy._string(base.get("ref"), label="base ref") != "main":
        raise RetrievalHardeningError(
            "retrieval only accepts pull requests targeting main"
        )

    raw_files = api.files(repository, pull_number)
    filenames = sorted(
        {
            raw["filename"]
            for raw in raw_files
            if isinstance(raw, dict) and isinstance(raw.get("filename"), str)
        }
    )
    skip_reason = legacy._skip_reason(pull, filenames)
    result = _base_result(
        repository=repository,
        pull_number=pull_number,
        head_sha=head_sha,
        base_sha=base_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        run_url=run_url,
        skip_reason=skip_reason,
    )
    if skip_reason:
        return result

    repository_payload = api.repository(repository)
    repository_visibility = legacy._string(
        repository_payload.get("visibility"),
        label="repository visibility",
        default="unknown",
    )
    documents, accepted_count, withheld_count, rejected = (
        legacy._load_documents(
            api,
            repository=repository,
            base_sha=base_sha,
            repository_visibility=repository_visibility,
        )
    )
    query = core.build_query_weights(
        title=legacy._string(pull.get("title"), label="pull title"),
        body=legacy._string(
            pull.get("body"), label="pull body", default=""
        ),
        filenames=filenames,
    )
    matches = core.retrieve(query, documents)
    body = render_privacy_safe_comment(
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
    comment_action, comment_id, duplicate_count = (
        reconcile_managed_comment(
            api,
            repository=repository,
            pull_number=pull_number,
            body=body,
        )
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
    if repository_visibility != "private":
        _redact_non_private_evidence(result)
    return result
