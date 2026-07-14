# CodeRabbit → Qodo exact-head fallback

## Purpose

`CML Reviewer Fallback` preserves review continuity when the canonical CodeRabbit bot reports that a pull-request review could not start because of a rate limit.

The workflow does not treat provider unavailability as approval. It requests one Qodo proxy review bound to the current full 40-character pull-request head SHA and records the real executor, requested reviewer, fallback reason, separate request/result provenance, and `merge_authority: false`.

## Trusted trigger

The workflow runs from the repository default branch on `issue_comment` `created` and `edited` events. It accepts a rate-limit signal only when both the comment author and event sender match the canonical CodeRabbit identity:

```text
login = coderabbitai[bot]
id    = 136622811
```

The comment must contain an explicit trusted rate-limit marker such as `Review limit reached`.

Spoofed comments are rejected and produce failure evidence. The workflow never checks out or executes pull-request code.

## Exact-head and duplicate controls

Before requesting Qodo, the workflow:

1. confirms that the comment belongs to an open pull request targeting `main`;
2. reads and validates the current full head SHA;
3. scans the complete issue-comment history;
4. authenticates any prior request through the exact `CML Reviewer Fallback` workflow run and its run-scoped evidence artifact;
5. serializes deliveries by pull-request number;
6. re-fetches the pull request immediately before posting;
7. rejects a request if the head, state, or base changed.

The generated request marker binds repository, pull request, exact head, workflow run ID, and run attempt. The generated request also states:

```text
requested reviewer = CodeRabbit
execution provider = Qodo
evidence kind      = proxy review
fallback reason    = RATE_LIMITED
merge authority    = false
```

## Authenticated lifecycle evidence

Comments authored as `github-actions[bot]` are not trusted merely because of that shared identity. A request marker or canonical status is accepted only when its referenced run:

- is named `CML Reviewer Fallback`;
- uses `.github/workflows/reviewer-fallback.yml`;
- is an `issue_comment` run from `main` in the expected repository;
- has the exact run attempt recorded by the marker;
- has completed successfully;
- exposes exactly one non-expired artifact named for the pull request, run, and attempt;
- contains `reviewer-fallback-evidence.json` matching repository, pull request, head SHA, run, attempt, request comment ID, and `merge_authority: false`.

The workflow has read-only Actions permission solely to verify this run-scoped capability. A public marker copied by another workflow is insufficient.

## Request and result provenance

The canonical evidence keeps the original request lifecycle immutable:

- `request_run_id`;
- `request_run_attempt`;
- `request_run_url`;
- `qodo_request_comment_id`;
- `request_timestamp`.

A later Qodo event records separate result provenance:

- `result_run_id`;
- `result_run_attempt`;
- `result_run_url`;
- `result_event_comment_id`;
- `result_timestamp`.

A result cannot overwrite the request run. Replayed or edited comments cannot complete an already completed lifecycle.

## Final Qodo result

A final result is accepted only from the canonical Qodo identity:

```text
login = qodo-code-review[bot]
id    = 151058649
```

The result must:

1. occur after the authenticated request comment;
2. contain one unambiguous structured reviewed-commit field outside quoted request text;
3. bind that field to the exact requested head;
4. arrive while the pull request still has that exact current head;
5. transition an incomplete lifecycle exactly once.

Arbitrary SHA mentions do not establish binding. Missing or conflicting structured reviewed-commit fields fail closed. A Qodo review of a superseded head is preserved as non-approval evidence with `passed: false`; it never publishes a success status.

## Evidence output

Every handled event writes `cml-reviewer-fallback-v2` JSON. The workflow uploads it with an exact-run/exact-attempt artifact name, maintains one canonical machine-readable pull-request status comment, and publishes the `CML Reviewer Fallback` commit status linked to the exact event run attempt.

A successful fallback status means only that proxy review evidence was delivered or recorded. It is not native CodeRabbit approval and does not authorize merge.

## Fail-closed outcomes

- spoofed CodeRabbit or Qodo identity → rejected;
- missing or short SHA → rejected;
- closed pull request or non-`main` base → rejected;
- superseded request head → rejected;
- superseded Qodo result → rejected as stale evidence;
- duplicate exact-head request → authenticated deterministic no-op;
- repeated Qodo completion → deterministic no-op;
- pre-request Qodo comment → rejected;
- missing, multiple, or mismatched reviewed-commit fields → rejected;
- forged Actions marker/status without matching workflow artifact → rejected;
- Qodo request failure → `PROVIDER_EVIDENCE_UNAVAILABLE`;
- malformed or ambiguous canonical status → workflow failure;
- workflow exception → structured artifact evidence with `passed: false`.

## YAML security policy

Bandit B506 is skipped only because it cannot distinguish the repository's duplicate-key loader derived from `yaml.SafeLoader`. A protected AST regression resolves module aliases and imported `load` functions, and rejects every production PyYAML load call unless its loader is proven to derive from `SafeLoader`. The Bandit config, security workflow, and semantic regression are protected by the trust-root manifest.

## Bootstrap boundary

This integration adds a new workflow and trusted helper, so its pull request intentionally changes protected trust-root paths. It requires a dedicated bootstrap review and explicit maintainer disposition. The workflow has no approval, merge, or auto-merge authority.
