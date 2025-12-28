# Audit Report Example (v0.5.1)

Input: `examples/secret_to_net_log.jsonl`

## Summary
- OK: 5
- WARN: 0
- FAIL: 1

## Findings

### FAIL — CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN
- Record: `b3`
- Reason: `send` after SECRET access (`b2`) has `parent_cause = null`
- permitted_by: `unobserved_parent`

Reconstructed context:
- SECRET access: `b2` (parent_cause: `b1`)
- NET_OUT: `b3` (parent_cause: null)  ← expected link missing

Interpretation:
- Functionally valid network send
- Causally invalid under SECRET → NET_OUT rule
