# CML Audit Findings Glossary

This glossary explains the built-in CML audit finding codes in plain language.
It is meant as a bridge for readers who want to understand audit output without
reading the source code first.

CML findings describe causal validity in a recorded action chain. They do not,
by themselves, prove intent, compromise, compliance status, or malicious
behavior.

## Quick Reference

| Code | Severity | Plain-language meaning |
| --- | --- | --- |
| `CML-AUDIT-R1-MISSING_PARENT` | FAIL | A record points to a parent record that is not present in the log. |
| `CML-AUDIT-R2-GAP_NOT_MARKED` | WARN | A record has no parent, but the gap is not explicitly marked. |
| `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN` | FAIL | A network action follows secret access without a causal link back to that secret access. |
| `CML-AUDIT-R4-AMBIGUOUS_ROOT` | WARN | A record looks like it may be a root event, but its root label is unclear or malformed. |

## `CML-AUDIT-R1-MISSING_PARENT`

**What it means:** A record has a `parent_cause` value, but that parent id does
not exist in the log being audited.

**Why it matters:** CML cannot reconstruct the full causal chain if a record
points to a missing parent. The action may have happened, but the log does not
show the authorization or responsibility step that supposedly caused it.

**Tiny example:** Record `deploy-2` says its parent is `approval-1`, but
`approval-1` is not included anywhere in the log.

**What to check next:**
- Confirm whether the missing parent record was dropped, filtered, or never
  written.
- Check for a typo in the `parent_cause` id.
- Verify that the audit input includes the complete log segment needed to
  reconstruct the chain.

## `CML-AUDIT-R2-GAP_NOT_MARKED`

**What it means:** A record has `parent_cause = null`, but it is not clearly
marked as an observed causal gap with `permitted_by = unobserved_parent`.

**Why it matters:** Some gaps are expected when a system cannot observe the
prior event. CML asks those gaps to be explicit. Without the marker, a reader
cannot tell whether the missing parent is intentional, accidental, or malformed.

**Tiny example:** Record `manual-review-7` has no parent cause, but its
`permitted_by` field says `operator-console` instead of `unobserved_parent`.

**What to check next:**
- If the missing parent is expected, mark it with
  `permitted_by = unobserved_parent`.
- If the record is a true root event, label it with the configured root prefix
  such as `root_event:<name>`.
- If a real parent exists, link the record to that parent with `parent_cause`.

## `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN`

**What it means:** In the same process context, CML saw a secret access followed
by a network action, but the network action does not reconstruct back to the
secret access through `parent_cause` links.

**Why it matters:** This rule checks whether sensitive access and later network
behavior are causally connected in the recorded lineage. It does not prove data
exfiltration; it flags that the log is missing the causal explanation CML
expects for this sensitive transition.

**Tiny example:** A process opens `/secrets/api.key`, then later sends data over
the network. The send record has no parent chain that links back to the secret
read.

**What to check next:**
- Inspect the chain for the network record and confirm whether it should link
  back to the secret access.
- Check whether intermediate records between secret access and network output
  are missing.
- Review the audit configuration for what counts as a secret and what counts as
  network output.

## `CML-AUDIT-R4-AMBIGUOUS_ROOT`

**What it means:** A record has no parent and looks like it may be intended as a
root event, but its `permitted_by` value does not match the expected root label
format.

**Why it matters:** Root events start a causal chain. If a root label is
ambiguous, CML cannot confidently distinguish a valid root from a malformed
missing-parent case.

**Tiny example:** A record uses `permitted_by = root_event` when CML expects a
label like `root_event:system_boot` or `root_event:user_request`.

**What to check next:**
- Use the configured root prefix format, usually `root_event:<cause>`.
- If the record is not a root, link it to its real parent with `parent_cause`.
- If the parent is intentionally unobserved, use `unobserved_parent` instead of
  a near-root label.

## Related Docs

- Audit semantics: [`../../vcml/audit.md`](../../vcml/audit.md)
- Decision code reference: [`../../DECISION_CODES.md`](../../DECISION_CODES.md)
- Benchmark fixtures and results: [`../../benchmarks/README.md`](../../benchmarks/README.md)
- Example audit report: [`../../examples/audit_report_example.md`](../../examples/audit_report_example.md)

