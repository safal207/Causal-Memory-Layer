## Review guidelines

- Focus on P0 and P1 correctness, security, determinism, and trust-contract failures.
- Reconstruct the intended invariants before judging the implementation.
- Treat green CI as evidence, not proof.
- Look for stale-SHA acceptance, cross-record substitution, ambiguous roots, duplicate-key or canonicalization ambiguity, replay, fail-open behavior, and evidence that is detached from the exact pull-request head.
- For every actionable finding, include a concrete failure path, the smallest regression test, and the minimal remediation.
- Do not report cosmetic issues.
- Bind any no-findings conclusion to the exact reviewed commit SHA.
- Review evidence never grants merge authority.
