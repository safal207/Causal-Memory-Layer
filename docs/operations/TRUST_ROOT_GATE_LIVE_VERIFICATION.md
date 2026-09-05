# CML Trust Root Gate live verification

This documentation-only change exists to verify repository protection for `main`.

## Required protected check

The branch protection rule or repository ruleset for `main` must require the exact status context:

```text
CML Trust Root Gate
```

## Verification procedure

1. Open this pull request against `main`.
2. Confirm `CML Trust Root Gate` runs from the protected default-branch implementation.
3. Confirm the reported target is bound to the exact workflow run and attempt.
4. Confirm GitHub blocks merge while the required status is missing or failing.
5. Record the pull request, exact head SHA, and immutable workflow run evidence in CML issue #173.

## Boundary

This file changes no runtime, package, security, or workflow behavior. It is an intentionally harmless probe for repository configuration only.
