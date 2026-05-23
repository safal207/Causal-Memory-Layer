# Agentic Workflow Causal Boundary Patterns

This research note maps causal boundary patterns that arise in agentic
workflows — cases where an AI agent or automation flow appears locally valid,
but the broader workflow boundary is causally questionable.

It builds on the causal-invalidity pattern taxonomy in
[docs/research/CAUSAL_INVALIDITY_PATTERNS.md](./CAUSAL_INVALIDITY_PATTERNS.md),
which covers current CML audit rules R1–R4. The patterns here extend that
taxonomy toward future benchmark and rule candidates.

> **CML supports causal review and accountability. It does not replace
> security products or guarantee compliance.**

---

## Background

The patterns in `CAUSAL_INVALIDITY_PATTERNS.md` focus on structural
failures detectable by current CML rules: missing parents, ambiguous roots,
unmarked gaps, and secret-to-network chains without lineage.

Agentic workflows introduce a second class of problem. An agent may produce
a trace that passes all current audit rules — every parent exists, every root
is properly declared — yet the broader workflow boundary is still causally
questionable. The action looks valid locally but is not properly authorized
by its causal lineage when the full workflow context is considered.

> A system can be functionally correct while being causally invalid.

---

## Pattern Summary

| # | Pattern | Functional outcome | Causal boundary question | Current CML status |
|---|---------|-------------------|-------------------------|--------------------|
| 1 | Stale parent cause reused | Action succeeds | Was an old approval reused for a new task? | Future benchmark/rule candidate |
| 2 | Rejected branch reused after human rejection | Tool call succeeds | Was a previously rejected path re-entered without new approval? | Future benchmark/rule candidate |
| 3 | Delegated agent action without authority handoff | Action succeeds | Was authority explicitly handed off to the agent? | Partially visible in trace model |
| 4 | Memory-derived action with missing evidence parent | Claim or action succeeds | Does the action trace back to a real observed event? | Future benchmark/rule candidate |
| 5 | Valid-looking local action inside an invalid thread | Action succeeds | Is the thread itself causally valid? | Partially visible in trace model |
| 6 | Remediation action that loses the original responsibility chain | Rollback succeeds | Is the remediation causally linked to the fault it addresses? | Future benchmark/rule candidate |

---

## Pattern 1 — Stale Parent Cause Reused

**Current CML status:** Future benchmark/rule candidate

### What happens

An agent completes workflow A and stores the final approved event ID.
Later, when starting workflow B — a different task — the agent reuses the
same event ID as its `parent_cause`. The approval was real, but it was
issued for a different workflow context. The new action inherits a causal
lineage it was never part of.

### Why ordinary logs may miss it

Both event IDs exist in the log. The parent reference resolves correctly.
No structural rule fires. Standard log analysis sees a valid parent pointer
and records the action as authorized.

### Causal boundary question

Was the approval that authorized this action issued for *this* workflow, or
was it recycled from a previous one?

### Minimal pseudo-trace

```jsonl
{"id":"wf-a-approval","timestamp":1690000001000000000,"actor":{"pid":100,"uid":0},"action":"exec","object":"/workflow/approve","permitted_by":"root_event:manager_approval","parent_cause":null}
{"id":"wf-b-action","timestamp":1690000900000000000,"actor":{"pid":200,"uid":1000},"action":"write","object":"/data/new_task_output.db","permitted_by":"parent_process_context","parent_cause":"wf-a-approval"}
```

The 15-minute gap and different PID suggest a workflow boundary crossing,
but current rules do not check temporal or workflow-scope validity.

### Expected reviewer interpretation

The action has a structurally valid parent. A reviewer should ask whether
the approval at `wf-a-approval` was scoped to workflow A only, and whether
reusing it for workflow B is intentional or an oversight.

---

## Pattern 2 — Rejected Branch Reused After Human Rejection

**Current CML status:** Future benchmark/rule candidate

### What happens

A human reviewer explicitly rejects a proposed agent action. The rejection
is logged. Later, the agent re-enters the same execution branch — perhaps
through a retry loop or a different code path — and completes the action
without obtaining new approval. The action succeeds. No structural rule fires
because the parent chain is intact.

### Why ordinary logs may miss it

The retry appears as a new event with a valid parent. The rejection event
exists in the log but is not referenced by the new action. Standard logs do
not check whether a completed action was previously rejected.

### Causal boundary question

Was this action branch previously rejected by a human reviewer, and if so,
was new approval obtained before re-entry?

### Minimal pseudo-trace

```jsonl
{"id":"plan-001","timestamp":1690000001000000000,"actor":{"pid":100,"uid":0},"action":"exec","object":"/agent/plan","permitted_by":"root_event:session_start","parent_cause":null}
{"id":"rejection-001","timestamp":1690000002000000000,"actor":{"pid":0,"uid":0},"action":"exec","object":"/human/reject","permitted_by":"root_event:human_review","parent_cause":"plan-001"}
{"id":"retry-001","timestamp":1690000010000000000,"actor":{"pid":100,"uid":0},"action":"write","object":"/data/output.db","permitted_by":"parent_process_context","parent_cause":"plan-001"}
```

`retry-001` traces back to `plan-001` correctly but ignores `rejection-001`.
Current rules do not check for superseding rejection events in the lineage.

### Expected reviewer interpretation

The write action has a valid structural parent. A reviewer should check
whether `rejection-001` in the same lineage supersedes the authority granted
by `plan-001`, and whether `retry-001` required fresh approval.

---

## Pattern 3 — Delegated Agent Action Without Authority Handoff

**Current CML status:** Partially visible in trace model

### What happens

A human or orchestrator delegates a task to an agent. The agent performs
an action and records the orchestrator event as its `parent_cause`. However,
no explicit authority handoff event exists in the log — the trace jumps
directly from the orchestrator decision to the agent action without a
delegation record.

### Why ordinary logs may miss it

The parent chain is intact. The agent correctly references the orchestrator
event. Standard logs treat this as a normal parent-child relationship and
record the action as authorized.

### Causal boundary question

Was authority explicitly handed off from the orchestrator to the agent, or
did the agent assume authority from a parent event that never delegated it?

### Minimal pseudo-trace

```jsonl
{"id":"orch-001","timestamp":1690000001000000000,"actor":{"pid":1,"uid":0},"action":"exec","object":"/orchestrator/decide","permitted_by":"root_event:user_request","parent_cause":null}
{"id":"agent-action-001","timestamp":1690000002000000000,"actor":{"pid":200,"uid":1000},"action":"write","object":"/data/result.db","permitted_by":"parent_process_context","parent_cause":"orch-001"}
```

A missing delegation event between `orch-001` and `agent-action-001` means
the agent inherited authority implicitly. A future CML rule could require
an explicit handoff record between different actor UIDs or PIDs.

### Expected reviewer interpretation

The action traces back to a valid orchestrator event. A reviewer should ask
whether the orchestrator event at `orch-001` explicitly granted write
authority to the agent PID, or whether the agent assumed it.

---

## Pattern 4 — Memory-Derived Action With Missing Evidence Parent

**Current CML status:** Future benchmark/rule candidate

### What happens

An agent retrieves information from a memory store or vector database and
uses it to justify an action. The action is recorded with a `parent_cause`
pointing to the memory retrieval event. However, the memory itself has no
traceable origin in the current log — it was written by a previous session
or an external process that is not represented in the trace.

### Why ordinary logs may miss it

The memory retrieval event exists and the parent reference resolves. The
action looks causally grounded. Standard logs do not check whether the
memory content itself has a verifiable origin in the current trace context.

### Causal boundary question

Does the action trace back to a real observed event in the current workflow,
or is it grounded only in memory content whose origin cannot be verified?

### Minimal pseudo-trace

```jsonl
{"id":"mem-retrieve-001","timestamp":1690000001000000000,"actor":{"pid":100,"uid":1000},"action":"read","object":"/memory/vector_store","permitted_by":"root_event:session_start","parent_cause":null}
{"id":"agent-action-001","timestamp":1690000002000000000,"actor":{"pid":100,"uid":1000},"action":"write","object":"/data/decision.db","permitted_by":"parent_process_context","parent_cause":"mem-retrieve-001"}
```

The memory at `/memory/vector_store` may contain claims from a previous
session. The current trace cannot verify their origin. A future CML rule
could flag memory-sourced actions as requiring an evidence parent beyond
the retrieval event itself.

### Expected reviewer interpretation

The action has a valid structural parent. A reviewer should ask whether
the memory content retrieved at `mem-retrieve-001` has a verifiable causal
origin in the current session, or whether it imports unverifiable claims
from outside the current trace boundary.

---

## Pattern 5 — Valid-Looking Local Action Inside an Invalid Thread

**Current CML status:** Partially visible in trace model

### What happens

An agent performs an action that is individually valid — the parent exists,
the root is properly declared, no gap is unmarked. But the thread the action
belongs to was itself started by an invalid or unauthorized event higher in
the chain. The local action passes all current audit rules while inheriting
a broken authorization from its ancestors.

### Why ordinary logs may miss it

Each individual event in the thread passes structural checks. The invalidity
is at the thread root, not at the local action. Standard log analysis checks
events individually and does not propagate thread-level invalidity downward.

### Causal boundary question

Is the thread this action belongs to itself causally valid, or does the
action inherit a broken authorization from an ancestor event?

### Minimal pseudo-trace

```jsonl
{"id":"bad-root-001","timestamp":1690000001000000000,"actor":{"pid":100,"uid":0},"action":"exec","object":"/agent/start","permitted_by":"root_event","parent_cause":null}
{"id":"mid-001","timestamp":1690000002000000000,"actor":{"pid":100,"uid":0},"action":"exec","object":"/agent/plan","permitted_by":"parent_process_context","parent_cause":"bad-root-001"}
{"id":"leaf-action-001","timestamp":1690000003000000000,"actor":{"pid":100,"uid":0},"action":"write","object":"/data/output.db","permitted_by":"parent_process_context","parent_cause":"mid-001"}
```

`bad-root-001` triggers `CML-AUDIT-R4-AMBIGUOUS_ROOT` (current rule).
`leaf-action-001` passes all current checks individually. A future rule
could propagate thread invalidity to all descendants.

### Expected reviewer interpretation

`leaf-action-001` is locally valid. A reviewer should trace the full
ancestor chain and check whether the thread root at `bad-root-001` was
properly authorized before treating the leaf action as causally legitimate.

---

## Pattern 6 — Remediation Action That Loses the Original Responsibility Chain

**Current CML status:** Future benchmark/rule candidate

### What happens

A fault occurs in a workflow. A remediation or rollback action is triggered
to correct it. The remediation succeeds and is logged. However, the
remediation event does not reference the fault event as its `parent_cause`
— it starts a new causal chain with a fresh root. The original
responsibility chain is lost.

### Why ordinary logs may miss it

The remediation is logged as a successful action. The new root event is
properly declared. No structural rule fires. Standard logs record the
remediation outcome without checking whether it is causally linked to the
fault it was meant to address.

### Causal boundary question

Is the remediation causally linked to the fault it addresses, or has the
original responsibility chain been silently dropped?

### Minimal pseudo-trace

```jsonl
{"id":"fault-001","timestamp":1690000001000000000,"actor":{"pid":100,"uid":1000},"action":"write","object":"/data/corrupt.db","permitted_by":"parent_process_context","parent_cause":"root-001"}
{"id":"remediation-001","timestamp":1690000060000000000,"actor":{"pid":200,"uid":0},"action":"write","object":"/data/corrupt.db","permitted_by":"root_event:ops_intervention","parent_cause":null}
```

`remediation-001` is a valid root event. But it has no reference to
`fault-001`, so the causal link between the fault and the fix is invisible
to any audit tool. A future CML rule could require remediation events to
reference the fault event they address.

### Expected reviewer interpretation

The remediation is structurally valid. A reviewer should ask whether
`remediation-001` was triggered by `fault-001` and, if so, why the
responsibility chain was not preserved in the trace.

---

## Relationship to Current CML Rules

| Pattern | Detectable today | How |
|---------|-----------------|-----|
| Stale parent cause reused | No | Future rule: timestamp/workflow-scope validation |
| Rejected branch reused | No | Future rule: rejection-supersession check |
| Delegated agent without handoff | Partially | R2 may fire if gap is unmarked; explicit handoff rule needed |
| Memory-derived action | No | Future rule: evidence-parent requirement for memory reads |
| Valid action in invalid thread | Partially | R4 fires on bad root; descendant propagation not yet implemented |
| Remediation loses responsibility | No | Future rule: fault-reference requirement for remediation events |

---

## Next Steps

These patterns are candidates for future benchmark fixtures and audit rules.
The suggested path forward is:

1. Add minimal executable fixtures under `benchmarks/fixtures/` for the
   two partially-visible patterns (3 and 5) where current rules already
   fire partially.
2. Define rule proposals for the four future candidates (1, 2, 4, 6) as
   issues before implementing them in the audit engine.
3. Expand the benchmark suite to cover the full taxonomy once rules are
   defined.

