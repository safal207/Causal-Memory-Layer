## Review guidelines

- Focus on P0 and P1 correctness, security, determinism, and trust-contract failures.
- Reconstruct the intended invariants before judging the implementation.
- Treat green CI as evidence, not proof.
- Every non-documentation pull request must state a concrete failure path, the invariant after the change, regression evidence, and residual risk. Unknown tracked formats fail closed into strict review.
- The `Causal PR Gate` must run on every pull request regardless of target branch, classify both sides of renames, bind its report to the exact base and head, and emit a cause-to-transition graph as review evidence. Only documentation-only changes use lightweight mode.
- The gate must reconfirm the target-branch tip before publishing final evidence. Every protected target branch must also require branches to be up to date before merging so evidence cannot remain eligible after the base advances.
- Workflow contract changes must include a mutation or regression test that would fail if the protection were removed.
- Look for stale base or head acceptance, cross-record substitution, ambiguous roots, duplicate-key or canonicalization ambiguity, replay, fail-open behavior, and evidence detached from the exact reviewed transition.
- For every actionable finding, include a concrete failure path, the smallest regression test, and the minimal remediation.
- Do not report cosmetic issues.
- Bind any no-findings conclusion to the exact reviewed base SHA and head SHA.
- Review evidence never grants merge authority.
