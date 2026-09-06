# CML Trusted CI v1

CML CI validates evidence about one immutable commit. A green check from a merge ref,
an older review, a skipped workflow, or a missing artifact is not accepted as evidence
for the current pull-request head.

## Required checks

| Required check | Responsibility | Fail-closed condition |
|---|---|---|
| `CML CI Gate` | Python 3.10-3.12 tests, coverage, deterministic contracts, bounded large-trace reliability | Any matrix lane, contract, exact-head assertion, or required artifact is missing or fails |
| `Build, check, install, and smoke-test package` | sdist/wheel build, strict metadata check, clean wheel install, CLI/import smoke, SHA-256 sums | The built distribution or package evidence is missing or invalid |
| `Security Gate` | Gitleaks, CodeQL, dependency audit, and Bandit | Any scanner fails, is skipped, or cannot establish the exact tested head |

Required pull-request workflows intentionally have no path filters. This prevents a
required check from appearing successful or absent merely because a change did not
match a path expression.

## Proof depth

1. **D0 — identity:** checkout the PR head repository and the full 40-character head
   SHA with credentials disabled, then compare `git rev-parse HEAD` to that SHA.
2. **D1 — executable tests:** run the supported Python matrix and enforce at least 70%
   coverage across `cml`, `cli`, and `api`.
3. **D2 — deterministic and adversarial contracts:** repeat safety and equilibrium
   evaluations under different hash seeds, compare byte-for-byte results, run bounded
   large-trace evidence, and mutation-test the CI workflow policy itself.
4. **D3 — package evidence:** build distributions, validate metadata, install the wheel
   into a clean environment, and publish SHA-256 sums.
5. **D4 — security evidence:** run source, secret, dependency, and CodeQL analysis.
6. **D5 — independent review:** Codex and mandatory reviewer evidence must refer to the
   current head SHA; unresolved or stale findings remain blockers.
7. **D6 — maintainer decision:** merge is a separate human-authorized action. CI never
   grants merge authority by itself.

## Evidence contract

Required workflows use immutable action SHAs, workflow-level `permissions: {}`,
explicit job permissions, bounded timeouts, and cancellation of superseded runs.
Evidence uploads use `if-no-files-found: error`.

`scripts/ci/build_evidence_manifest.py` creates a deterministic manifest containing the
target repository, source repository, exact tested SHA, workflow/run identity, and the
size and SHA-256 digest of every collected report. Symlinks, invalid SHAs, empty evidence,
missing required patterns, and case-insensitive duplicate paths fail closed.

`scripts/ci/verify_workflow_contract.py` structurally verifies the three required
workflows. Its tests mutate action pins, checkout credentials, exact-head binding,
artifact policy, and event trust boundary to prove those downgrades are rejected.

## Review boundary

This version deliberately keeps asynchronous AI-review collection outside executable
CI. The current-head review rule remains mandatory, but CI does not treat comments,
summaries, provider availability, or model output as authorization. A later reviewer
publisher may automate D5 only after its identity, provenance, freshness, mutation, and
stale-run controls have their own tested contract.
