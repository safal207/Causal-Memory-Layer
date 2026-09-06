# CodeRabbit → Qodo exact-head fallback

## Purpose

`CML Reviewer Fallback` preserves review continuity when the canonical
CodeRabbit bot reports that a pull-request review could not start because of a
rate limit.

The workflow requests one Qodo proxy review bound to the current full
40-character pull-request head SHA. It records the real executor, requested
reviewer, fallback reason, separate request/result provenance, and
`merge_authority: false`. Provider unavailability is never approval.

## Trusted architecture

The security state machine lives in:

```text
.github/trust-root/scripts/reviewer_fallback.py
```

A protected event adapter lives in:

```text
.github/trust-root/scripts/reviewer_fallback_entrypoint.py
```

The adapter performs only two bounded tasks:

1. normalize supported native GitHub review events into the core's canonical
   comment contract;
2. authenticate fallback artifacts from the same explicit event allowlist.

It then calls the existing `core.process_event()` state machine. It does not
replace identity checks, exact-head validation, duplicate detection, status
publication, reviewed-SHA extraction, or provider routing.

The core remains intrinsically strict and enforces:

- canonical CodeRabbit/Qodo login and numeric identities;
- sender/author agreement before provider routing;
- untrusted rate-limit text ignored before write-capable API calls;
- open PR, `main` base, full exact-head SHA, and immediate head re-fetch;
- authenticated Actions request/status comments through exact run artifacts;
- Qodo `edited` events rejected before lifecycle completion;
- exactly one structured reviewed-commit occurrence;
- stale and superseded results fail closed;
- successful evidence never publishes a success commit status.

## Native event surfaces

The workflow declares the three GitHub surfaces on which a review provider may
publish native PR output:

```text
issue_comment
pull_request_review
pull_request_review_comment
```

Supported actions are:

```text
issue_comment:                created, edited
pull_request_review:          submitted, edited
pull_request_review_comment:  created, edited
```

The write-capable job has a narrower provider matrix:

| Event surface | CodeRabbit | Qodo |
| --- | --- | --- |
| `issue_comment` | allowed | allowed |
| `pull_request_review` | allowed | allowed |
| `pull_request_review_comment` | allowed | not started |

Qodo inline comments are partial findings or replies, not canonical completed
reviews. Excluding them at the workflow boundary avoids intentional failed runs
for every inline Qodo comment. The protected adapter still maps such a payload
to the core's rejected edited-result path if invoked directly or by a future
caller.

Arbitrary text cannot start the write-capable job. The workflow checks the
event-specific provider login first; the core then independently verifies the
numeric identity and sender/author agreement.

A CodeRabbit rate-limit signal from any supported native surface is normalized
into the same strict core path. The signal is accepted only when author and
sender both match:

```text
login = coderabbitai[bot]
id    = 136622811
```

The body must contain an explicit unavailability marker such as
`Review limit reached`. Matching text from any other identity is ignored without
comments, statuses, or provider requests.

## Qodo result surfaces

A complete Qodo result may arrive as either:

- a newly created top-level PR comment; or
- a submitted pull-request review.

Both are normalized to the core `created` lifecycle event and must satisfy the
same exact-head and provenance checks.

An inline `pull_request_review_comment` from Qodo cannot complete the canonical
review lifecycle. It is excluded by the normal workflow filter and rejected by
the adapter/core boundary if presented directly.

The accepted Qodo identity remains:

```text
login = qodo-code-review[bot]
id    = 151058649
```

## Exact-head and duplicate controls

Before requesting Qodo, the core:

1. confirms an open pull request targeting `main`;
2. validates the full current head SHA;
3. scans the complete issue-comment history;
4. discards non-Actions request-marker comments before parsing marker syntax;
5. skips malformed or unauthenticated Actions candidates without denying
   service;
6. authenticates a prior request through its exact successful workflow run and
   run-scoped artifact;
7. serializes deliveries by pull-request number;
8. re-fetches the PR immediately before posting;
9. rejects changed state, base, or head.

The request marker binds repository, PR, exact head, run ID, and run attempt.
The request states:

```text
requested reviewer = CodeRabbit
execution provider = Qodo
evidence kind      = proxy review
fallback reason    = RATE_LIMITED
merge authority    = false
```

## Authenticated lifecycle evidence

A `github-actions[bot]` comment is not trusted merely because of its shared
identity. A request marker or canonical status is accepted only when its
referenced run:

- is named `CML Reviewer Fallback`;
- uses `.github/workflows/reviewer-fallback.yml`;
- has an event in the explicit supported allowlist;
- executed from `main` in the expected repository;
- has the exact recorded run attempt;
- completed successfully;
- exposes exactly one non-expired artifact named for PR, run, and attempt;
- contains one `reviewer-fallback-evidence.json` matching repository, PR, head,
  run, attempt, request comment, and `merge_authority: false`.

Artifact enumeration is bounded. Ten complete pages of 100 artifacts cause
explicit exhaustion rather than silent truncation.

## Request and result provenance

Immutable request provenance contains:

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

A result cannot overwrite the request run. Replayed results are deterministic
no-ops. Edited Qodo comments and inline Qodo comments cannot complete the
lifecycle.

## Evidence output and non-authority

Every handled event writes `cml-reviewer-fallback-v2` JSON and uploads an
exact-run/exact-attempt artifact. The workflow maintains one canonical
machine-readable PR comment.

The fallback **never publishes a successful commit status**. Request delivery,
duplicate handling, and a successful Qodo review therefore cannot become a
branch-protection merge signal. Failure and provider-unavailable outcomes may
publish failure/error statuses linked to the exact event attempt.

The comment and artifact are evidence only. They do not authorize merge.

## Live-validation boundary

The implementation is unit- and contract-tested across all three event
surfaces. Final acceptance of issue #168 still requires a new real
post-merge CodeRabbit rate-limit event proving exactly one request, exact-run
artifacts, no success merge status, and fail-closed replay behavior.
