# Decision Codes (CML Audit)

Codes are stable identifiers for audit outcomes.

## Severity
- OK
- WARN
- FAIL

## Codes

### CML-AUDIT-R1-MISSING_PARENT (FAIL)
`parent_cause` references a record id that does not exist in the log.

### CML-AUDIT-R2-GAP_NOT_MARKED (WARN)
A causal gap exists (`parent_cause = null`) but `permitted_by` is not `unobserved_parent`.

### CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN (FAIL)
A SECRET access occurred and a NET_OUT occurred later, but NET_OUT does not link back to SECRET via `parent_cause`.

### CML-AUDIT-R4-AMBIGUOUS_ROOT (WARN)
A record has `parent_cause = null` but is not clearly labeled as a root event (`root_event:*`).
