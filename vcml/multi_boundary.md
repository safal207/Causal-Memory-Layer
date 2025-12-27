# Multi-Boundary Memory (v0.5)

This document defines the minimal semantics for a **multi-boundary causal chain** that links:

```
exec  →  secret access (open/read)  →  network egress (connect/send)
```

The goal is to show that vCML is **system memory** across boundaries, not just process history.

## Boundaries (v0.5 canonical)

1. **exec**
2. **open / read** (for secret access)
3. **connect / send** (for network egress)

## Definition of SECRET

A **SECRET** is any object with classification **SECRET**.

Classification is a **semantic hint** (not policy, not enforcement), derived from cues such as:

- path pattern (e.g. `/secrets/*`, `*.key`)
- mount label
- environment variable
- configuration key

## Causal Rules

### 1) Chain rule
If egress traffic is derived from secret data, then the **send** record MUST have a
`parent_cause` that reconstructs the path to the secret access:

```
exec → open/read (SECRET) → connect/send
```

### 2) Causal invalidity
If a **SECRET** access occurs and is followed by **NET_OUT**, but the NET_OUT record has
no linked `parent_cause` (or points elsewhere), the behavior is **causally questionable**.

## Notes

- This is **memory**, not **blocking**.
- Detection is only an example usage of the memory, not an enforcement product.
- CTAG can be attached to records for compact semantic routing, but v0.5 does not require
  computing CTAG in code.
