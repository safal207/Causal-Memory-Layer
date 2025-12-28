# vCML Audit Semantics (v0.5.1)

This document defines a **read-only audit layer** for vCML causal logs.

Audit answers:
- Is the log **causally coherent**?
- Where are the **causal gaps**?
- Which invariants are violated?

Audit does NOT:
- block actions
- enforce policies
- decide correctness of outcomes
- replace security products

> A system may be functionally correct while being causally invalid.

---

## Inputs

A vCML audit consumes:
- JSONL causal records (append-only)
- optional semantic config defining expected chains (see `examples/audit_config_example.yaml`)

---

## Core Concepts

### Causal chain
A chain is a path of `parent_cause` links reconstructing:
- origin (root_event or observed parent)
- intermediate causal checkpoints (e.g. SECRET access)
- terminal boundary (e.g. NET_OUT)

### Causal gap
A record is a **gap** when:
- it is not a root event, and
- `parent_cause` is null (or unresolved), and
- `permitted_by = unobserved_parent` (recommended signal)

### Causal integrity
Causal integrity means:
- references exist
- chain is reconstructible
- expected links are present when semantics require them

---

## Decision Codes

Audit emits standardized decision codes (read-only). See `DECISION_CODES.md`.

Common outcomes:
- OK: chain coherent for the examined rule
- WARN: incomplete causality (gap) but not a hard violation
- FAIL: expected causal link missing (causally invalid under the rule)

---

## Rules (canonical v0.5.1)

### R1 — Reference Integrity
**FAIL** if a record’s `parent_cause` points to a non-existent id.

- Code: `CML-AUDIT-R1-MISSING_PARENT`

### R2 — Gap Marking Consistency
If `parent_cause = null` and record is not a known root event,
then `permitted_by` SHOULD be `unobserved_parent`.

- Code: `CML-AUDIT-R2-GAP_NOT_MARKED` (WARN)

### R3 — SECRET → NET_OUT Chain (semantic)
If there exists:
- a SECRET read/open event `S`, and later
- a NET_OUT event `N` (connect/send) in the same process context,
then `N` MUST have a `parent_cause` that reconstructs a path back to `S`
(or to a cause derived from `S`).

- Code: `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN` (FAIL)

Notes:
- This is semantic: it does not prove dataflow, only checks missing causal links
- Configuration may define what counts as SECRET and what counts as NET_OUT

### R4 — Root Event Identification
A record with `parent_cause = null` is treated as root only if:
- `permitted_by` starts with `root_event:` (recommended), OR
- config marks it as root explicitly.

- Code: `CML-AUDIT-R4-AMBIGUOUS_ROOT` (WARN)

---

## Output Format (human-readable)

An audit report SHOULD include:
- summary counts (OK/WARN/FAIL)
- list of violations with ids and short explanation
- optional “reconstructed chain” snippet for each FAIL

See `examples/audit_report_example.md`.
