# Memory Learning Loop live probe

## Summary

This documentation-only pull request verifies the post-merge CML Memory Learning Loop on a real GitHub event after the protected workflow has reached `main`.

## Root cause

The bootstrap pull request could validate implementation, permissions, tests, and trust-root boundaries, but its own merge event could not execute a workflow that was not yet present on the default branch.

## Design

Merge this documentation-only probe into `main` and require the protected learning workflow to create exactly one reviewable draft Memory Pack proposal bound to the probe pull request head and merge commit.

## Validation

Acceptance requires:

- a successful `CML Memory Learning Loop` run from the merged default-branch implementation;
- an exact-run/exact-attempt learning evidence artifact;
- one generated `cml-learning/...` branch;
- one draft PR changing only the expected `.cml/memory/cycles/...json` file;
- a valid `cml-memory-pack-v1` pack ID;
- explicit CI, Python Package Validation, and Security Baseline runs on the generated branch;
- a repeated event or validation replay producing no duplicate proposal;
- no direct write of accepted memory to `main`;
- no merge or execution authority.

## Boundaries

This probe changes documentation only. The generated Memory Pack remains a team-visible proposal with `contains_private_data: true` until a maintainer reviews it. The probe does not require accepting or merging the generated memory proposal.
