# Docker + Causal Memory Demo Walkthrough

This walkthrough shows how to run the CML Audit API locally with Docker and
submit a minimal causal log for audit. By the end you will see the core CML
idea in action:

> **A system can be functionally correct while being causally invalid.**

See also: [docs/deploy/README.md](../deploy/README.md)

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose installed
- `curl` available in your terminal

---

## Step 1 — Start the API

```bash
docker compose up --build
```

Wait until you see:

```
INFO:     Application startup complete.
```

---

## Step 2 — Health check

Open a **new terminal** and run:

```bash
curl http://localhost:8080/health
```

Expected response:

```json
{"status": "ok", "version": "0.5.1"}
```

---

## Step 3 — Understanding a CausalRecord

Before submitting a log, it helps to know what a record looks like.
Every CausalRecord has these required fields:

| Field | Meaning |
|---|---|
| `id` | Unique ID for this event |
| `timestamp` | Time in nanoseconds |
| `actor` | Who did it — process info (`pid`, `uid`, optionally `ppid`) |
| `action` | What was done — `exec`, `read`, `write`, `connect`, etc. |
| `object` | What was acted on — a file path, address, etc. |
| `permitted_by` | What permission authorized this action |
| `parent_cause` | ID of the previous event that caused this one (`null` for root events) |

A **root event** has `parent_cause: null` and `permitted_by` starting with
`root_event:` — it is the starting point of a causal chain.

---

## Step 4 — Submit a broken causal chain

The log below has two records:

- `demo-evt-001` — a valid root event (manager approval)
- `demo-evt-002` — a write action whose `parent_cause` points to
  `demo-evt-MISSING`, which does not exist in the log

```bash
curl -s -X POST http://localhost:8080/audit \
  -H "Content-Type: application/json" \
  -d '{
    "log": "{\"id\":\"demo-evt-001\",\"timestamp\":1690000001000000000,\"actor\":{\"pid\":1000,\"uid\":0,\"ppid\":null},\"action\":\"exec\",\"object\":\"/usr/bin/approve\",\"permitted_by\":\"root_event:manager_approval\",\"parent_cause\":null}\n{\"id\":\"demo-evt-002\",\"timestamp\":1690000002000000000,\"actor\":{\"pid\":1001,\"uid\":1000,\"ppid\":1000},\"action\":\"write\",\"object\":\"/data/funds.db\",\"permitted_by\":\"parent_process_context\",\"parent_cause\":\"demo-evt-MISSING\"}",
    "format": "json"
  }'
```

Expected response:

```json
{
    "summary": {
        "total": 2,
        "ok": 1,
        "warnings": 0,
        "failures": 1,
        "passed": false
    },
    "findings": [
        {
            "code": "CML-AUDIT-R1-MISSING_PARENT",
            "severity": "FAIL",
            "record_id": "demo-evt-002",
            "message": "parent_cause 'demo-evt-MISSING' does not exist in the log."
        }
    ]
}
```

**What this means:**

`demo-evt-002` (the write to `/data/funds.db`) executed successfully as an
operation. But CML found that its claimed parent `demo-evt-MISSING` does not
exist in the log — the causal chain is broken. The audit rule
`CML-AUDIT-R1-MISSING_PARENT` fires with severity `FAIL`.

The action is **functionally correct, causally invalid**.

---

## Step 5 — Submit a valid causal chain

Now fix the chain by pointing `parent_cause` to the real root event `demo-evt-001`:

```bash
curl -s -X POST http://localhost:8080/audit \
  -H "Content-Type: application/json" \
  -d '{
    "log": "{\"id\":\"demo-evt-001\",\"timestamp\":1690000001000000000,\"actor\":{\"pid\":1000,\"uid\":0,\"ppid\":null},\"action\":\"exec\",\"object\":\"/usr/bin/approve\",\"permitted_by\":\"root_event:manager_approval\",\"parent_cause\":null}\n{\"id\":\"demo-evt-002\",\"timestamp\":1690000002000000000,\"actor\":{\"pid\":1001,\"uid\":1000,\"ppid\":1000},\"action\":\"write\",\"object\":\"/data/funds.db\",\"permitted_by\":\"parent_process_context\",\"parent_cause\":\"demo-evt-001\"}",
    "format": "json"
  }'
```

Expected response:

```json
{
    "summary": {
        "total": 2,
        "ok": 2,
        "warnings": 0,
        "failures": 0,
        "passed": true
    },
    "findings": []
}
```

`demo-evt-002` now traces back to `demo-evt-001` — a complete, authorized
causal chain. `passed: true`.

---

## The CML Principle

Comparing Step 4 and Step 5 makes the core idea concrete:

- The **action** (`write` to `/data/funds.db`) was identical in both cases
- The **operation would have succeeded** either way
- Only the **causal lineage** differed

Standard logging records *what happened*. CML checks *whether what happened
was causally permitted*. A missing `parent_cause` is invisible to operational
metrics but surfaces immediately in a CML audit.

---

## Stopping the API

```bash
docker compose down
```

To also remove the persisted SQLite volume:

```bash
docker compose down -v
```

---

See also: [docs/deploy/README.md](../deploy/README.md)