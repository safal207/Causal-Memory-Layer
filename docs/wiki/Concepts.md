# Concepts — What Is Causal Memory?

This page explains CML without requiring any code knowledge.
If you want to understand *why* this project exists, start here.

---

## The problem: systems that lie by omission

Imagine a company runs software that processes financial data.
Every night, a process reads customer records, performs calculations, and sends a report to an external server.

The system works perfectly. No errors. No crashes. Compliance logs show all accesses were authorized.

But one day, a slightly different process does something subtly wrong:
it reads a secret API key, then immediately sends data to an external server —
with no recorded connection between the two actions.

From the outside, both behaviors look identical.
Both processes are authorized. Both complete without errors.
The difference is invisible to any system that only tracks *what happened*.

**CML makes this difference visible.**

---

## The core idea: *why* not just *what*

Most audit logs record:
- **What** happened: `"read /secrets/api_key"`
- **When** it happened: `"2025-02-01T11:00:00Z"`
- **Who** did it: `"pid=5220, uid=1000"`

CML adds one more field: **why** this action is causally linked to what came before.

```json
{
  "id": "a3",
  "action": "read",
  "object": { "path": "/secrets/api_key", "classification": "SECRET" },
  "actor": { "pid": 4102 },
  "permitted_by": "a2",
  "parent_cause": "a2"
}
```

The `parent_cause` field says: *"this read happened because of record a2."*
You can follow the chain backwards from any action all the way to its origin.

---

## Causal validity vs. functional correctness

This is the central distinction CML makes:

> **A system may be functionally correct while being causally invalid.**

A process can read a secret and send data to the network.
Both operations may be fully authorized.
But if there is no recorded causal link between them, the system cannot prove
that the network send was a *consequence* of the secret read — rather than a coincidence happening at the same time.

CML doesn't say "this is wrong." It says: "we can't trace *why* this happened."

---

## What a causal chain looks like

Here's a well-formed chain. Each action leads causally to the next:

```
root_event:init
      │
      ▼
[a1] exec /usr/bin/reporter    (permitted by: root)
      │
      ▼
[a2] open /secrets/api_key     (permitted by: fs:read, caused by: a1)
      │
      ▼
[a3] read /secrets/api_key     (caused by: a2)
      │
      ▼
[a4] connect 203.0.113.10:443  (permitted by: net:egress, caused by: a3)
      │
      ▼
[a5] send to 203.0.113.10:443  (caused by: a3)
```

You can trace the entire chain: the network send happened *because* the secret was read,
which happened *because* the file was opened, which happened *because* the process started.

---

## What a causal gap looks like

Now compare this to the invalid chain:

```
root_event:init
      │
      ▼
[b1] exec /usr/bin/uploader    (caused by: root)
      │
      ▼
[b2] read /secrets/token       (caused by: b1)

[b3] send to 198.51.100.45:8443   ← parent_cause: null
                                     permitted_by: "unobserved_parent"
```

Record `b3` has no causal link to `b2`. The data left the machine,
the secret was read, but the log cannot show us they are connected.

This is what CML flags as a **causal gap** — specifically, a violation of rule R3:
*a NET_OUT after a SECRET read must have a traceable causal path back to that read.*

---

## What CML is NOT

Understanding what CML deliberately avoids is as important as understanding what it does.

| CML is... | CML is NOT... |
|---|---|
| A read-only audit tool | A security enforcement engine |
| A memory of *why* | A policy of *what is allowed* |
| Language-agnostic | Tied to any runtime, OS, or language |
| A record of intent | A judge of intent |
| Append-only | Mutable or retroactive |

CML never blocks a process, never rejects a request, never modifies a log.
It only tells you: *is this chain coherent?*

---

## Why this matters

**For developers:** when something goes wrong, you don't just know *that* data left — you know *what caused it* to leave. The chain of custody is in the log.

**For auditors:** "the process was authorized" and "the action was causally justified" are different claims. CML makes the second claim verifiable.

**For architects:** causal validity is a property of the system's design, not just its runtime behavior. A system that cannot produce valid causal logs has a structural gap in its accountability.

---

## The key invariant

Read this once and remember it:

> **Functional correctness ≠ Causal validity.**

A system where everything works but the causal links are broken is not auditable.
CML is the layer that makes auditing possible.
