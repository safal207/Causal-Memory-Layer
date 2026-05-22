# LTP ↔ CML Bridge: Causal Legitimacy Over Time

Status: architecture bridge and positioning note.

## Short thesis

**CML validates whether an action was causally legitimate.**

**LTP preserves whether that legitimacy remains stable over time.**

In other words:

```text
CML answers: Was this action allowed?
LTP answers: Is this still the same legitimate thread?
```

Together, they define a stronger trust model for long-running AI systems:

```text
Causal legitimacy at action time + continuity of legitimacy over time.
```

---

## Why this bridge matters

Many AI failures are not single-step failures.

They emerge across time:

- context changes;
- memory changes;
- policy changes;
- authority changes;
- tools change;
- responsibility is handed off;
- a rejected branch is later reused;
- a previous assumption silently becomes stale.

A single action may look locally valid while the larger thread has drifted.

That is the gap between CML and LTP:

```text
CML checks local causal legitimacy.
LTP checks longitudinal trust continuity.
```

## Layer responsibilities

| Layer | Core question | Primary failure class |
| --- | --- | --- |
| LTP / L-THREAD | Is this action still inside the same legitimate thread? | trust drift, branch drift, context discontinuity |
| T-Trace | What happened in a replayable trace? | missing or non-reproducible event evidence |
| CML | Why was this action allowed? | missing parent cause, invalid permission lineage, broken responsibility chain |
| CaPU | Should this decision proceed? | unsafe or unauthorized execution boundary |
| TTM DB | What is the immutable ground truth? | mutable or conflicting history |

Short form:

```text
LTP preserves continuity.
T-Trace records events.
CML validates permission lineage.
CaPU gates execution.
TTM DB preserves history.
```

---

## CML: action-level causal validity

CML focuses on whether an individual action or state transition is grounded in a valid causal chain.

It asks:

- Was there a valid parent cause?
- Which policy permitted the action?
- Was the data scope allowed?
- Was responsibility preserved?
- Is there a causal gap?
- Did the action look successful while being causally invalid?

Example:

```json
{
  "action": "recommend_limit_change",
  "permitted_by": "policy.credit_risk.v3",
  "parent_cause": "analyst_request.req_219",
  "data_scope": "risk_summary_only",
  "result": "causally_valid"
}
```

CML verdict:

```text
PROCEED / AUDIT / BLOCK / REJECT
```

The key distinction:

```text
Operational success does not imply causal legitimacy.
```

---

## LTP: thread-level trust continuity

LTP focuses on whether a long-running workflow, agent thread, or decision chain remains inside the same legitimate continuity boundary.

It asks:

- Is this the same thread?
- Did the context branch change?
- Was a rejected branch reused?
- Did the authority context drift?
- Did the policy version change?
- Did memory introduce stale or invalid assumptions?
- Can the thread be replayed deterministically enough for audit?

Example:

```json
{
  "thread_id": "ltp_thread_4821",
  "branch_id": "risk_review.current",
  "previous_step_hash": "sha256:...",
  "policy_context": "credit_risk.v3",
  "authority_context": "human_analyst.supervised",
  "trust_state": "continuous",
  "replay_profile": "deterministic_audit"
}
```

LTP verdict:

```text
CONTINUE / AUDIT / FREEZE / REJECT_BRANCH
```

The key distinction:

```text
A locally valid action can still belong to a broken trust thread.
```

---

## Combined failure scenario

A fintech analyst asks an AI assistant to recommend a customer limit change.

### Day 1

The AI assistant operates under:

```text
thread_id = customer_limit_review_4821
policy = credit_risk.v3
authority = analyst_supervised
branch = current_review
```

CML sees:

```text
valid analyst request
valid policy
approved data scope
human final approval required
```

Verdict:

```text
CML: PROCEED
LTP: CONTINUE
```

### Day 14

The agent reuses memory from an old branch where:

```text
policy = credit_risk.v2
branch = rejected_recommendation
authority = auto_approval_experiment
```

The immediate action may still contain a parent cause and a policy reference, so a shallow audit might look acceptable.

But LTP detects continuity drift:

```text
policy context changed
branch lineage changed
rejected branch reused
trust state no longer continuous
```

Combined verdict:

```text
CML: AUDIT
LTP: REJECT_BRANCH
Final: BLOCK or HUMAN_REVIEW_REQUIRED
```

This is the bridge claim:

```text
CML validates the action.
LTP validates the continuity boundary around the action.
```

---

## Violation vocabulary

Possible LTP-side violation codes:

| Code | Meaning |
| --- | --- |
| `LTP-THREAD-DISCONTINUITY` | The action is not connected to the expected thread lineage. |
| `LTP-POLICY-CONTEXT-DRIFT` | The policy context changed without explicit transition. |
| `LTP-MEMORY-BRANCH-DRIFT` | The agent relied on memory from another branch. |
| `LTP-REJECTED-BRANCH-REUSED` | A previously rejected branch influenced the current action. |
| `LTP-REPLAY-MISMATCH` | Replay cannot reproduce the expected thread state. |
| `LTP-AUTHORITY-CONTEXT-CHANGED` | Authority moved from one actor or mode to another without a valid handoff. |
| `LTP-RESPONSIBILITY-HANDOFF-BROKEN` | Responsibility was not preserved across a handoff. |

Possible CML-side violation codes remain action-level:

| Code | Meaning |
| --- | --- |
| `CML-AUDIT-R1-MISSING_PARENT` | A parent cause is missing from the log. |
| `CML-AUDIT-R2-GAP_NOT_MARKED` | A causal gap exists but is not explicitly marked. |
| `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN` | Secret access and network behavior lack a valid causal link. |
| `CML-AUDIT-R4-AMBIGUOUS_ROOT` | A root event label is malformed or unclear. |

---

## Reviewer-facing explanation

A strong reviewer explanation is:

```text
CML catches causally invalid actions.
LTP catches continuity-invalid threads.
```

Or:

```text
CML asks whether an AI action had a valid reason.
LTP asks whether that reason remained valid across time, memory, policy, and branch transitions.
```

This turns the CML/LTP relationship into a clean two-layer model:

```text
Action legitimacy + thread continuity = stronger AI auditability.
```

---

## Relationship to the broader stack

```text
Model / Agent
   ↓
LTP / L-THREAD
thread continuity, branch identity, replay boundary
   ↓
T-Trace
replayable event evidence
   ↓
CML
causal permission and responsibility lineage
   ↓
CaPU
decision gating and execution boundary
   ↓
TTM DB
immutable historical substrate
   ↓
Audit / Incident Review / Governance
```

The central idea:

```text
Without CML, we may know what happened but not why it was allowed.
Without LTP, we may know why a local action was allowed but not whether the thread remained legitimate over time.
```

---

## Bottom line

CML is the layer of **causal legitimacy**.

LTP is the layer of **longitudinal trust continuity**.

Together:

```text
CML makes actions accountable.
LTP keeps accountability continuous.
```
