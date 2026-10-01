# vCML Causal Record Format (Draft v0)

This document defines the **minimal semantic structure** of a vCML causal record.

The format describes *what must be remembered*, not how it is transported or stored.

---

## Design Principles

- Append-only
- Immutable once written
- Language-agnostic
- Transport-agnostic
- Storage-agnostic

The record captures **permission and responsibility**, not outcomes.

---

## Minimal Causal Record

A vCML causal record MUST be able to express:

### Core Fields

- **id**
  - Unique identifier of this causal record
  - Monotonic or UUID-based, represented as a string (for example, `"1"` or a UUID string)

- **timestamp**
  - Time when the boundary was crossed
  - Nanoseconds or comparable precision

- **actor**
  - Entity that initiated the action
  - Example fields:
    - pid
    - uid
    - gid
    - process name (optional)

- **action**
  - The type of boundary crossed
  - Examples:
    - exec
    - open
    - write
    - connect
    - send

- **object**
  - Target of the action
  - Examples:
    - path hash or inode
    - network address and port
    - file descriptor identifier

- **permitted_by**
  - Reference to the permission, capability, policy, or prior cause
  - Semantic reference, not enforcement logic

- **parent_cause**
  - Identifier of the causal record that enabled this action
  - A string matching the parent record's `id`, or null/omitted when there is no parent reference
  - Allows causal chains to be reconstructed

---

## Integrity (Future Field)

- **integrity**
  - Placeholder for hash or signature
  - Ensures causal record integrity in later versions
  - Not required in v0

---

## Notes

- No cryptography is required at this stage
- No schema serialization is mandated (JSON, binary, etc.)
- The emphasis is on **meaning**, not performance

- The Python SDK and JSONL/API boundaries reject non-string `id` values and
  non-string, non-null `parent_cause` values as invalid input. They do not coerce
  values: numeric `1` must not silently become string `"1"` and collide with an
  existing identity. SDK construction and graph indexing raise
  `InvalidRecordIdentityError` (a `ValueError`); the HTTP API returns 422.

- `permitted_by` is a semantic reference (id or string), not a policy evaluation result.
- If `parent_cause` is null due to a causal gap (not a root event), `permitted_by` SHOULD be "unobserved_parent".
- `parent_cause` may be null for explicit root events
  (e.g. system boot, init, or break-glass actions).
