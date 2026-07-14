# CodeRabbit → Qodo exact-head fallback

## Purpose

`CML Reviewer Fallback` preserves review continuity when the canonical CodeRabbit bot reports that a pull-request review could not start because of a rate limit.

The workflow requests one Qodo proxy review bound to the current full 40-character pull-request head SHA. It records the real executor, requested reviewer, fallback reason, separate request/result provenance, and `merge_authority: false`. Provider unavailability is never approval.

## Intrinsically strict core

The security invariants live in:

```text
.github/trust-root/scripts/reviewer_fallback.py
```

The core is safe when imported directly or executed through its own CLI. It intrinsically enforces:

- only canonical CodeRabbit/Qodo identities reach provider handlers;
- untrusted rate-limit text is ignored before write-capable API calls;
- untrusted request-marker comments are skipped before marker parsing;
- malformed or unauthenticated Actions-authored markers are skipped without blocking legitimate fallback processing;
- Qodo `edited` events cannot complete a lifecycle;
- exactly one structured reviewed-commit occurrence is required;
- artifact pagination exhaustion fails explicitly;
- successful evidence delivery never publishes a success commit status.

The workflow executes a thin protected delegate:

```text
.github/trust-root/scripts/reviewer_fallback_entrypoint.py
```

The delegate only loads the core, re-exports its API, and calls `core.main()`. It contains no security monkey patches or alternate behavior. Both files are protected by exact Git blob identity, and direct-core regression tests prove the same guarantees without the delegate.

## Trusted trigger

The write-capable workflow job starts only when the issue comment belongs to a pull request and the comment author login is exactly one of:

```text
coderabbitai[bot]
qodo-code-review[bot]
```

Arbitrary comment text cannot start the job. The workflow-level filter is only the first boundary: the core additionally requires canonical numeric IDs and sender/author agreement before routing CodeRabbit or Qodo provider events.

A CodeRabbit rate-limit signal is accepted only when both the comment author and event sender match:

```text
login = coderabbitai[bot]
id    = 136622811
```

The trusted bot comment must also contain an explicit rate-limit marker such as `Review limit reached`. A matching phrase from any other identity is ignored as unrelated input, without creating comments, statuses, or provider requests. Pull-request code is never checked out or executed.

## Exact-head and duplicate controls

Before requesting Qodo, the workflow:

1. confirms an open pull request targeting `main`;
2. validates the full current head SHA;
3. scans the complete issue-comment history;
4. discards non-Actions request-marker comments before parsing marker syntax;
5. skips malformed or unauthenticated Actions-authored candidates instead of letting unrelated workflow comments deny service;
6. authenticates a valid prior request through the exact successful workflow run and its run-scoped evidence artifact;
7. serializes deliveries by pull-request number;
8. re-fetches the pull request immediately before posting;
9. rejects changed state, base, or head.

A malformed marker from any unrelated commenter or workflow cannot block legitimate fallback processing. If more than one fully authenticated request exists for the same exact head, the verifier still fails closed as an ambiguous lifecycle.

The request marker binds repository, pull request, exact head, run ID, and run attempt. The request also states:

```text
requested reviewer = CodeRabbit
execution provider = Qodo
evidence kind      = proxy review
fallback reason    = RATE_LIMITED
merge authority    = false
```

## Authenticated lifecycle evidence

A `github-actions[bot]` comment is not trusted merely because of its shared identity. A request marker or canonical status is accepted only when its referenced run:

- is named `CML Reviewer Fallback`;
- uses `.github/workflows/reviewer-fallback.yml`;
- is an `issue_comment` run from `main` in the expected repository;
- has the exact recorded run attempt;
- completed successfully;
- exposes exactly one non-expired artifact named for the PR, run, and attempt;
- contains one `reviewer-fallback-evidence.json` matching repository, PR, head, run, attempt, request comment, and `merge_authority: false`.

Artifact enumeration is bounded. Ten complete pages of 100 artifacts cause explicit pagination exhaustion instead of silent truncation.

## Request and result provenance

The canonical evidence keeps request provenance immutable:

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

A result cannot overwrite the request run. Replayed comments are deterministic no-ops. Edited Qodo comments are rejected before lifecycle processing.

## Final Qodo result

A result is accepted only from the canonical Qodo identity:

```text
login = qodo-code-review[bot]
id    = 151058649
```

It must:

1. arrive through an `issue_comment` `created` event;
2. occur after the authenticated request;
3. contain exactly one structured reviewed-commit occurrence outside quoted request text;
4. bind to the exact requested head;
5. arrive while that head remains current;
6. transition an incomplete lifecycle exactly once.

Missing, repeated, conflicting, or arbitrary SHA mentions fail closed. A superseded review is preserved as non-approval evidence with `passed: false`.

## Evidence output and non-authority

Every handled event writes `cml-reviewer-fallback-v2` JSON and uploads an exact-run/exact-attempt artifact. The workflow also maintains one canonical machine-readable PR comment.

The fallback **never publishes a successful commit status**. Therefore request delivery, duplicate handling, and a successful Qodo review cannot become a branch-protection merge signal. Failure and provider-unavailable outcomes may publish failure/error statuses linked to the exact event attempt.

The comment and artifact are evidence only. They do not authorize merge.

## YAML security policy

Bandit B506 cannot distinguish the repository's duplicate-key loader derived from `yaml.SafeLoader`. The security workflow explicitly loads a protected `.bandit` policy, while a protected AST regression:

- resolves PyYAML module aliases and imported function aliases;
- requires `load` and `load_all` to use exactly one loader proven to derive from `SafeLoader`;
- strictly forbids `unsafe_load`, `unsafe_load_all`, `full_load`, and `full_load_all`;
- permits `safe_load` and `safe_load_all`.

## Bootstrap boundary

This integration adds a workflow and trusted helpers, so its PR intentionally changes protected trust-root paths. It requires dedicated bootstrap review and explicit maintainer disposition. No workflow or reviewer has approval, merge, or auto-merge authority.
