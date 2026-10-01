#!/usr/bin/env python3
"""Collect live, read-only evidence for every open CML Memory Proposal.

Network collection is intentionally separated from trust decisions. For each
proposal this collector validates the frozen pack, rebuilds it from current
GitHub observations, then compares evidence components before handing an
immutable source core to the pure v0.3 adapter.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

import memory_learning_core as learning
import memory_retrieval_core as retrieval

from cml.experimental.memory_proposal_queue import audit
from cml.experimental.memory_proposal_queue_planner import plan
from cml.experimental.memory_proposal_queue_revalidation import build_planner_record

API = "https://api.github.com"
TITLE_PREFIX = "memory: learn from merged PR #"
SOURCE_PR_RE = re.compile(r"^memory: learn from merged PR #(\d+)$")
SOURCE_MERGE_RE = re.compile(r"^- source merge: `([0-9a-f]{40})`$", re.MULTILINE)
SOURCE_HEAD_RE = re.compile(r"^- source head: `([0-9a-f]{40})`$", re.MULTILINE)
MEMORY_PATH_RE = re.compile(r"^- memory path: `([^`]+)`$", re.MULTILINE)
PACK_ID_RE = re.compile(r"^- pack ID: `([0-9a-f]{64})`$", re.MULTILINE)
REQUIRED_EVIDENCE = (
    "source-pr",
    "source-files",
    "source-reviews",
    "source-checks",
    "source-merge",
)
DESCRIPTIVE_EVIDENCE = ("source-pr",)
OPERATIONAL_EVIDENCE = ("source-reviews", "source-checks")
MUTABLE_EVIDENCE = (*DESCRIPTIVE_EVIDENCE, *OPERATIONAL_EVIDENCE)
SELF_CHECK_NAME = "Propose merged-cycle memory"


class CollectionError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


class GitHubReader:
    def __init__(self, token: str) -> None:
        if not token:
            raise CollectionError("GITHUB_TOKEN is required")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "cml-memory-queue-revalidation-v0.3",
        }

    def get(self, path: str) -> Any:
        url = path if path.startswith("https://") else API + path
        request = Request(url, headers=self._headers)
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            raise CollectionError(f"GitHub API {exc.code} for {url}: {detail}") from exc

    def paginate_list(self, path: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        page = 1
        separator = "&" if "?" in path else "?"
        while True:
            payload = self.get(f"{path}{separator}per_page=100&page={page}")
            if not isinstance(payload, list):
                raise CollectionError(f"expected list response for {path}")
            rows = [item for item in payload if isinstance(item, dict)]
            result.extend(rows)
            if len(payload) < 100:
                return result
            page += 1

    def check_runs(self, repository: str, head_sha: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        page = 1
        while True:
            payload = self.get(
                f"/repos/{repository}/commits/{head_sha}/check-runs?filter=latest&per_page=100&page={page}"
            )
            if not isinstance(payload, dict):
                raise CollectionError("check-runs response must be an object")
            rows = payload.get("check_runs")
            total = payload.get("total_count")
            if not isinstance(rows, list) or not isinstance(total, int):
                raise CollectionError("check-runs response is incomplete")
            result.extend(item for item in rows if isinstance(item, dict))
            if len(result) >= total or not rows:
                return result
            page += 1


def _required(pattern: re.Pattern[str], text: str, field: str) -> str:
    match = pattern.search(text)
    if match is None:
        raise CollectionError(f"proposal body missing {field}")
    return match.group(1)


def _parse_proposal(pull: dict[str, Any]) -> dict[str, Any]:
    title = pull.get("title")
    body = pull.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        raise CollectionError("proposal title/body must be strings")
    source_match = SOURCE_PR_RE.fullmatch(title)
    if source_match is None:
        raise CollectionError(f"unexpected proposal title: {title!r}")

    number = pull.get("number")
    draft = pull.get("draft")
    head = pull.get("head")
    html_url = pull.get("html_url")
    created_at = pull.get("created_at")
    if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
        raise CollectionError("proposal number must be positive")
    if draft is not True:
        raise CollectionError(f"proposal #{number} must remain draft")
    if not isinstance(head, dict) or not isinstance(head.get("sha"), str):
        raise CollectionError(f"proposal #{number} missing head SHA")
    if not isinstance(html_url, str) or not isinstance(created_at, str):
        raise CollectionError(f"proposal #{number} missing URL/timestamp")

    return {
        "proposal_pr": number,
        "source_pr": int(source_match.group(1)),
        "source_merge": _required(SOURCE_MERGE_RE, body, "source merge"),
        "source_head": _required(SOURCE_HEAD_RE, body, "source head"),
        "memory_path": _required(MEMORY_PATH_RE, body, "memory path"),
        "pack_id": _required(PACK_ID_RE, body, "pack ID"),
        "proposal_head": head["sha"],
        "proposal_url": html_url,
        "created_at": created_at,
    }


def _pack_text(
    reader: GitHubReader,
    *,
    repository: str,
    path: str,
    ref: str,
) -> tuple[str, str]:
    encoded_path = quote(path, safe="/")
    encoded_ref = quote(ref, safe="")
    payload = reader.get(
        f"/repos/{repository}/contents/{encoded_path}?ref={encoded_ref}"
    )
    if not isinstance(payload, dict):
        raise CollectionError("contents response must be an object")
    content = payload.get("content")
    encoding = payload.get("encoding")
    blob_sha = payload.get("sha")
    if not isinstance(content, str) or encoding != "base64" or not isinstance(blob_sha, str):
        raise CollectionError("Memory Pack contents response is incomplete")
    try:
        text = base64.b64decode(content).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise CollectionError("Memory Pack is not valid UTF-8/base64") from exc
    return text, blob_sha


def _evidence_digests(pack: Mapping[str, Any]) -> dict[str, str]:
    raw = pack.get("evidence")
    if not isinstance(raw, list):
        raise CollectionError("Memory Pack evidence must be a list")
    result: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise CollectionError("Memory Pack evidence entry must be an object")
        evidence_id = item.get("id")
        digest = item.get("digest")
        if not isinstance(evidence_id, str) or not isinstance(digest, str):
            raise CollectionError("Memory Pack evidence entry missing id/digest")
        if evidence_id in result:
            raise CollectionError(f"duplicate Memory Pack evidence id: {evidence_id}")
        result[evidence_id] = digest
    required = set(REQUIRED_EVIDENCE)
    if not required.issubset(result):
        missing = ",".join(sorted(required - set(result)))
        raise CollectionError(f"Memory Pack missing required evidence: {missing}")
    return result


def _source_core_digest(
    *,
    repository: str,
    source_pr: int,
    source_head: str,
    source_merge: str,
    source_files_digest: str,
) -> str:
    """Hash immutable source bindings, excluding mutable PR narrative/check data."""

    return learning.sha256_json(
        {
            "repository": repository,
            "source_pr": source_pr,
            "source_head": source_head,
            "source_merge": source_merge,
            "source_files_digest": source_files_digest,
        }
    )


def _self_completion_explains_checks(
    checks: list[dict[str, Any]],
    original_checks_digest: str,
) -> bool:
    """Test one narrow self-observation TOCTOU hypothesis without asserting it."""

    normalized = learning.normalize_checks(checks)
    found = False
    hypothetical: list[dict[str, Any]] = []
    for item in normalized:
        candidate = dict(item)
        if candidate.get("name") == SELF_CHECK_NAME:
            candidate["status"] = "in_progress"
            candidate["conclusion"] = None
            found = True
        hypothetical.append(candidate)
    return found and learning.sha256_json(hypothetical) == original_checks_digest


def collect(repository: str, token: str) -> dict[str, Any]:
    reader = GitHubReader(token)
    captured_at = _utc_now()

    main_ref = reader.get(f"/repos/{repository}/git/ref/heads/main")
    if not isinstance(main_ref, dict):
        raise CollectionError("main ref response must be an object")
    obj = main_ref.get("object")
    if not isinstance(obj, dict) or not isinstance(obj.get("sha"), str):
        raise CollectionError("main ref missing commit SHA")
    main_sha = obj["sha"]

    open_pulls = reader.paginate_list(f"/repos/{repository}/pulls?state=open")
    memory_pulls = [
        pull
        for pull in open_pulls
        if isinstance(pull.get("title"), str)
        and pull["title"].startswith(TITLE_PREFIX)
    ]
    if not memory_pulls:
        raise CollectionError("no open automatic Memory Proposals found")

    proposals = sorted(
        (_parse_proposal(pull) for pull in memory_pulls),
        key=lambda item: item["proposal_pr"],
    )

    queue_snapshot = {
        "schema": "cml.memory-proposal-queue.snapshot.v0.1",
        "captured_at": captured_at,
        "main_revision": main_sha,
        "reported_total_count": len(proposals),
        "proposals": [
            {
                "proposal_pr": item["proposal_pr"],
                "source_pr": item["source_pr"],
                "source_merge": item["source_merge"],
                "pack_id": item["pack_id"],
                "created_at": item["created_at"],
                "state": "open",
                "draft": True,
                "lesson_status": "proposed",
                "visibility": "team",
                "contains_private_data": True,
                "merge_authority": False,
                "execution_authority": False,
            }
            for item in proposals
        ],
    }
    queue_result = audit(queue_snapshot)

    records: list[dict[str, Any]] = []
    full_replay_matches = 0
    stable_core_matches = 0
    ancestry_matches = 0
    operational_drift_count = 0
    descriptive_drift_count = 0
    mutable_drift_count = 0
    self_completion_drift_count = 0
    generator_contract_drift_count = 0
    component_mismatches: Counter[str] = Counter()

    for item in proposals:
        pack_text, pack_blob_sha = _pack_text(
            reader,
            repository=repository,
            path=item["memory_path"],
            ref=item["proposal_head"],
        )
        document = retrieval.parse_memory_pack(
            pack_text,
            path=item["memory_path"],
            repository=repository,
        )
        if document.pack_id != item["pack_id"]:
            raise CollectionError(
                f"proposal #{item['proposal_pr']} body/Memory Pack identity mismatch"
            )
        if document.source_commit != item["source_merge"]:
            raise CollectionError(
                f"proposal #{item['proposal_pr']} source commit mismatch"
            )
        original_pack = json.loads(pack_text)
        if not isinstance(original_pack, dict):
            raise CollectionError("Memory Pack must decode to an object")
        original_evidence = _evidence_digests(original_pack)

        source_pull = reader.get(f"/repos/{repository}/pulls/{item['source_pr']}")
        if not isinstance(source_pull, dict):
            raise CollectionError("source pull response must be an object")
        if source_pull.get("merged_at") is None:
            raise CollectionError(
                f"source PR #{item['source_pr']} is no longer recorded as merged"
            )
        current_merge = source_pull.get("merge_commit_sha")
        if current_merge != item["source_merge"]:
            raise CollectionError(
                f"source PR #{item['source_pr']} merge SHA contradicts proposal"
            )
        head = source_pull.get("head")
        if not isinstance(head, dict) or head.get("sha") != item["source_head"]:
            raise CollectionError(
                f"source PR #{item['source_pr']} head SHA contradicts proposal"
            )
        current_head = head["sha"]

        files = reader.paginate_list(
            f"/repos/{repository}/pulls/{item['source_pr']}/files"
        )
        reviews = reader.paginate_list(
            f"/repos/{repository}/pulls/{item['source_pr']}/reviews"
        )
        checks = reader.check_runs(repository, item["source_head"])
        replayed = learning.build_memory_pack(
            repository=repository,
            pull=source_pull,
            files=files,
            reviews=reviews,
            check_runs=checks,
        )
        replayed_pack_id = replayed["pack_id"]
        replayed_evidence = _evidence_digests(replayed)

        full_replay_match = replayed_pack_id == item["pack_id"]
        full_replay_matches += int(full_replay_match)
        changed_components = sorted(
            component
            for component in set((*original_evidence, *replayed_evidence))
            if original_evidence.get(component) != replayed_evidence.get(component)
        )
        component_mismatches.update(changed_components)

        expected_source_core = _source_core_digest(
            repository=repository,
            source_pr=item["source_pr"],
            source_head=item["source_head"],
            source_merge=item["source_merge"],
            source_files_digest=original_evidence["source-files"],
        )
        observed_source_core = _source_core_digest(
            repository=repository,
            source_pr=item["source_pr"],
            source_head=current_head,
            source_merge=current_merge,
            source_files_digest=replayed_evidence["source-files"],
        )
        stable_core_match = expected_source_core == observed_source_core
        stable_core_matches += int(stable_core_match)

        operational_changed = [
            component
            for component in changed_components
            if component in OPERATIONAL_EVIDENCE
        ]
        descriptive_changed = [
            component
            for component in changed_components
            if component in DESCRIPTIVE_EVIDENCE
        ]
        mutable_changed = [
            component
            for component in changed_components
            if component in MUTABLE_EVIDENCE
        ]
        operational_drift_count += int(bool(operational_changed))
        descriptive_drift_count += int(bool(descriptive_changed))
        mutable_drift_count += int(bool(mutable_changed))

        self_completion_drift = (
            "source-checks" in changed_components
            and _self_completion_explains_checks(
                checks,
                original_evidence["source-checks"],
            )
        )
        self_completion_drift_count += int(self_completion_drift)
        generator_contract_drift = bool(
            not full_replay_match and not changed_components
        )
        generator_contract_drift_count += int(generator_contract_drift)

        compare = reader.get(
            f"/repos/{repository}/compare/{item['source_merge']}...{main_sha}"
        )
        if not isinstance(compare, dict):
            raise CollectionError("compare response must be an object")
        compare_status = compare.get("status")
        ancestor = compare_status in {"ahead", "identical"}
        ancestry_matches += int(ancestor)

        record = build_planner_record(
            {
                "repository": repository,
                "proposal_pr": item["proposal_pr"],
                "source_pr": item["source_pr"],
                "source_merge": item["source_merge"],
                "current_main_revision": main_sha,
                "pack_id": item["pack_id"],
                "validated_pack_id": document.pack_id,
                "replayed_pack_id": replayed_pack_id,
                "expected_source_core_digest": expected_source_core,
                "observed_source_core_digest": observed_source_core,
                "full_pack_replay_match": full_replay_match,
                "changed_evidence_components": changed_components,
                "self_observation_completion_drift": self_completion_drift,
                "source_exists": True,
                "source_ancestor_of_main": ancestor,
                "evidence_refs": [
                    item["proposal_url"],
                    f"https://github.com/{repository}/blob/{item['proposal_head']}/{item['memory_path']}",
                    f"https://github.com/{repository}/pull/{item['source_pr']}",
                    f"https://github.com/{repository}/commit/{item['source_merge']}",
                    f"https://github.com/{repository}/compare/{item['source_merge']}...{main_sha}",
                    f"https://github.com/{repository}/commit/{item['source_head']}/checks",
                    f"git-blob:{pack_blob_sha}",
                ],
            }
        )
        records.append(record)

    planner_input = {
        "schema": "cml.memory-proposal-queue.revalidation-input.v0.2",
        "source_audit_schema": queue_result["schema"],
        "source_audit_digest": queue_result["snapshot_digest"],
        "current_main_revision": main_sha,
        "captured_at": captured_at,
        "synthetic": False,
        "expected_record_count": len(records),
        "records": records,
    }
    planner_result = plan(planner_input)
    if planner_result["record_count"] != len(proposals):
        raise CollectionError("Planner record coverage does not match live proposal count")
    if planner_result["authority_granted"] is not False:
        raise CollectionError("Planner unexpectedly granted authority")

    fitness_counts = Counter(
        decision["canonical_fitness"]["status"]
        for decision in planner_result["decisions"]
    )
    applicability_counts = Counter(
        record["applicability"]["status"] for record in records
    )
    quality_counts = Counter(record["quality"]["readiness"] for record in records)

    summary = {
        "schema": "cml.memory-proposal-queue.live-revalidation-summary.v0.3",
        "captured_at": captured_at,
        "main_revision": main_sha,
        "proposal_count": len(proposals),
        "planner_record_count": planner_result["record_count"],
        "planner_group_count": planner_result["group_count"],
        "full_pack_replay_match_count": full_replay_matches,
        "full_pack_replay_drift_count": len(proposals) - full_replay_matches,
        "stable_source_core_match_count": stable_core_matches,
        "stable_source_core_drift_count": len(proposals) - stable_core_matches,
        "mutable_evidence_drift_count": mutable_drift_count,
        "descriptive_pr_metadata_drift_count": descriptive_drift_count,
        "operational_evidence_drift_count": operational_drift_count,
        "self_observation_completion_drift_count": self_completion_drift_count,
        "generator_contract_drift_count": generator_contract_drift_count,
        "evidence_component_mismatch_counts": dict(sorted(component_mismatches.items())),
        "source_ancestor_of_main_count": ancestry_matches,
        "source_not_ancestor_of_main_count": len(proposals) - ancestry_matches,
        "applicability_counts": dict(sorted(applicability_counts.items())),
        "quality_readiness_counts": dict(sorted(quality_counts.items())),
        "fitness_counts": dict(sorted(fitness_counts.items())),
        "semantic_acceptance_evidence": "NOT_COLLECTED",
        "authority_granted": False,
    }

    return {
        "queue_snapshot": queue_snapshot,
        "queue_audit": queue_result,
        "planner_input": planner_input,
        "planner_result": planner_result,
        "summary": summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect live CML queue revalidation evidence"
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("artifacts/memory-queue-revalidation"),
    )
    args = parser.parse_args()

    if not args.repository or "/" not in args.repository:
        print("repository must be owner/name", file=sys.stderr)
        return 2
    token = os.environ.get(args.token_env, "")

    try:
        result = collect(args.repository, token)
    except (
        CollectionError,
        retrieval.RetrievalError,
        learning.LearningLoopError,
        ValueError,
    ) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in result.items():
        path = args.out_dir / f"{name.replace('_', '-')}.json"
        path.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    print(json.dumps(result["summary"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
