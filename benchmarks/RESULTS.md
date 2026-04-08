# CML Safety-Eval Results

Deterministic benchmark report generated from `benchmarks/fixtures`.

## Summary

- Total cases: **6**
- Matched cases: **6**
- Mismatches: **0**
- Expected passed / failed: **3 / 3**
- Predicted passed / failed: **3 / 3**

## Per-case results

| case_id | expected | predicted | status | expected_codes | predicted_codes |
|---|---|---|---|---|---|
| valid-grounded-secret-net-chain | pass | pass | PASS | <none> | <none> |
| missing-parent-reference | fail | fail | PASS | CML-AUDIT-R1-MISSING_PARENT | CML-AUDIT-R1-MISSING_PARENT |
| unmarked-causal-gap | pass | pass | PASS | CML-AUDIT-R2-GAP_NOT_MARKED | CML-AUDIT-R2-GAP_NOT_MARKED |
| ambiguous-root-authority | pass | pass | PASS | CML-AUDIT-R4-AMBIGUOUS_ROOT | CML-AUDIT-R4-AMBIGUOUS_ROOT |
| secret-to-network-without-lineage | fail | fail | PASS | CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN | CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN |
| custom-rule-missing-session-ancestor | fail | fail | PASS | CML-AUDIT-R5-NET-OUTSIDE-SESSION | CML-AUDIT-R5-NET-OUTSIDE-SESSION |
