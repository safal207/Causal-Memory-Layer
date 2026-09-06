# Memory Learning Loop: blocked pull-request fallback

GitHub repositories may disable the Actions setting **Allow GitHub Actions to create and approve pull requests**.

When that setting is disabled, the protected Memory Learning Loop can still create the deterministic generated branch and Memory Pack through the Contents API, but GitHub rejects the final `POST /pulls` request with HTTP 403.

## Safe fallback

The loop recognizes only the exact GitHub error:

```text
GitHub Actions is not permitted to create or approve pull requests.
```

Before creating a fallback review issue, it re-authenticates the immutable generated artifact:

- expected branch derived from source PR number and merge SHA;
- expected `.cml/memory/cycles/...json` path;
- canonical `pack_id` recomputation;
- source repository and merge-commit binding;
- exact source-head binding inside the graph;
- `visibility=team`;
- `contains_private_data=true`;
- `merge_authority=false`;
- `execution_authority=false`;
- one proposed lesson requiring human review.

If any check fails, the run fails closed and no issue is created.

## Fallback outcome

A verified blocked run records:

```text
PROPOSAL_BRANCH_CREATED_PR_BLOCKED
```

and creates one idempotent issue containing:

- source PR, head SHA, and merge SHA;
- generated branch and memory path;
- exact pack ID;
- the repository setting that must be enabled;
- explicit no-main-write and no-authority boundaries.

The workflow receives `issues: write` only for this fallback. It does not dispatch CI, package, or security validation until an actual PR exists.

## Restoring full automation

Enable the repository Actions setting and re-run the Learning Loop for the source PR. The ordinary state machine discovers the existing exact generated branch, opens the draft PR, and dispatches validation workflows without regenerating or force-updating the Memory Pack.

An unrelated HTTP 403 never activates the fallback and remains a failed run.
