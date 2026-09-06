# Memory Learning Loop full-automation proof

## Summary

This documentation-only pull request verifies that the repository setting allowing GitHub Actions to create pull requests is enabled and that the protected CML Memory Learning Loop can complete its full review-first cycle without manual recovery.

## Root cause

Earlier live validation proved deterministic Memory Pack and branch creation, but the repository setting blocked the final Actions-created pull request call.

## Design

Merge this documentation-only probe into `main`. The protected Learning Loop must create one draft Memory PR automatically from the resulting merge event.

## Validation

Acceptance requires:

- a successful `CML Memory Learning Loop` run;
- one generated `cml-learning/...` branch;
- one automatically created draft PR;
- exactly one `.cml/memory/cycles/...json` changed file;
- exact source head and merge commit bindings;
- a valid deterministic `pack_id`;
- `visibility=team` and `contains_private_data=true`;
- a proposed lesson requiring human review;
- explicit CI, Python Package Validation, and Security Baseline runs on the generated branch;
- no fallback issue for this source PR;
- no direct write of accepted memory to `main`;
- no merge, approval, or execution authority.

## Boundaries

This probe changes documentation only. The automatically generated Memory PR remains a proposal and must not be merged automatically.
