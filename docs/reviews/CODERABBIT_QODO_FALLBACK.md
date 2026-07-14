# CodeRabbit → Qodo exact-head fallback

## Purpose

`CML Reviewer Fallback` preserves review continuity when the canonical CodeRabbit bot reports that a pull-request review could not start because of a rate limit.

The workflow does not treat provider unavailability as approval. It requests one Qodo proxy review bound to the current full 40-character pull-request head SHA and records the real executor, requested reviewer, fallback reason, and `merge_authority: false`.

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
3. scans the complete issue-comment history for a trusted GitHub Actions request marker for that exact SHA;
4. serializes deliveries by pull-request number;
5. re-fetches the pull request immediately before posting;
6. rejects a request if the head, state, or base changed.

The generated request contains:

```text
requested reviewer = CodeRabbit
execution provider = Qodo
evidence kind      = proxy review
fallback reason    = RATE_LIMITED
merge authority    = false
```

## Evidence

Every handled event writes `cml-reviewer-fallback-v1` JSON bound to:

- repository and pull-request number;
- exact head SHA;
- workflow run ID and run attempt;
- original CodeRabbit comment ID;
- Qodo request comment ID and timestamp;
- stale or superseded state;
- final Qodo comment identity, exact reviewed SHA, and normalized outcome when available.

The workflow uploads this JSON with an exact-run/exact-attempt artifact name. It also maintains one canonical machine-readable pull-request status comment and publishes the `CML Reviewer Fallback` commit status linked to the exact workflow attempt.

## Final Qodo result

A final result is recorded only from the canonical Qodo bot identity:

```text
login = qodo-code-review[bot]
id    = 151058649
```

The bot comment must contain the exact SHA from the canonical fallback status. Results without that binding are ignored. A successful fallback status means only that proxy review evidence was delivered or recorded; it is not native CodeRabbit approval and does not authorize merge.

## Fail-closed outcomes

- spoofed CodeRabbit identity → rejected;
- missing or short SHA → rejected;
- closed pull request or non-`main` base → rejected;
- superseded head → rejected;
- duplicate exact-head request → deterministic no-op;
- Qodo request failure → `PROVIDER_EVIDENCE_UNAVAILABLE`;
- malformed or ambiguous canonical status → workflow failure;
- workflow exception → structured artifact evidence with `passed: false`.

## Bootstrap boundary

This integration adds a new workflow and trusted helper, so its pull request intentionally changes protected trust-root paths. It requires a dedicated bootstrap review and explicit maintainer disposition. The workflow has no approval, merge, or auto-merge authority.
