# CodeRabbit → Qodo missed-event recovery

## Purpose

The native `CML Reviewer Fallback` event path remains the primary path. This recovery layer handles the narrower case where GitHub retains a canonical CodeRabbit rate-limit comment but no corresponding fallback workflow lifecycle was created.

Recovery is evidence continuity, not approval. It never grants merge or auto-merge authority and never publishes a successful merge status.

## Two-stage design

An hourly read-oriented discovery job scans open pull requests targeting `main`.

It dispatches a write-capable reconciliation run only when all of the following are true:

1. the pull request is open and targets `main`;
2. the comment author is exactly `coderabbitai[bot]` with numeric identity `136622811`;
3. the comment contains a recognized review-unavailability marker;
4. the comment contains the current full 40-character pull-request head SHA;
5. no authenticated Qodo fallback request already exists for that exact head;
6. a final PR re-fetch confirms that state, base, and head did not change.

The discovery run does not post comments or statuses. It dispatches the same protected workflow with the selected PR number and canonical CodeRabbit comment ID.

## Concurrency and exactly-once behavior

Native provider events and dispatched recovery runs use the same per-PR concurrency group. A native webhook and a recovery dispatch therefore serialize on the pull-request number.

The strict core then performs its existing authenticated request lookup. If another run already created the exact-head request, the later run becomes `DUPLICATE_DELIVERY_NOOP` rather than creating another Qodo review.

## Delayed-event freshness

A delayed rate-limit comment is not rebound to a newer pull-request head. Recovery requires the current full SHA to be present as a standalone value in the trusted CodeRabbit comment body.

A comment bound only to a superseded SHA is ignored during discovery and rejected during reconciliation.

## Artifact boundary

Request artifacts may originate from the native review event surfaces or from `workflow_dispatch` reconciliation. Scheduled discovery artifacts are not accepted as request lifecycle evidence because discovery cannot create a Qodo request.

Every accepted request still binds:

- repository;
- pull-request number;
- exact head SHA;
- workflow run and attempt;
- request comment ID;
- `merge_authority: false`.

## Limitations

Recovery does not retroactively create evidence for closed pull requests. Historical events such as PR #178 remain diagnostic evidence only. Final acceptance of issue #168 still requires a fresh post-merge event on an open, unchanged exact head.
