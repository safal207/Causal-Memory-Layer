# Causal Invalidity Patterns for Agent Action Logs

This research note maps causal-invalidity patterns that are invisible to
ordinary operational logs but detectable by CML audit rules.

It builds on the Docker demo walkthrough in
[docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md](../demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md)
and references the benchmark fixtures in `benchmarks/fixtures/`.

> **CML supports causal review and accountability. It does not replace
> security products or guarantee compliance.**

See also: [docs/deploy/README.md](../deploy/README.md)

---

## Background

Standard operational logs record *what happened* — which process ran, which
file was written, which connection was made. They do not record *whether the
action had a valid permission and responsibility lineage*.

CML audit rules check causal coherence: every action should trace back
through a chain of permitted causes to a declared root event. When that
chain is broken, missing, or ambiguous, CML surfaces a finding — even when
the action itself succeeded.

> A system can be functionally correct while being causally invalid.

---

## Pattern Summary

| # | Pattern | Rule | Finding Code | Severity | Why ordinary logs miss it |
|---|---------|------|--------------|----------|--------------------------|
| 1 | Missing parent cause | R1 | `CML-AUDIT-R1-MISSING_PARENT` | FAIL | Logs record the action but not whether the claimed parent exists |
| 2 | Ambiguous root event | R4 | `CML-AUDIT-R4-AMBIGUOUS_ROOT` | WARN | Logs record the label but do not validate the root event format |
| 3 | Unmarked causal gap | R2 | `CML-AUDIT-R2-GAP_NOT_MARKED` | WARN | Logs record the action but not that the lineage is unverifiable |
| 4 | Secret access without network chain | R3 | `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN` | FAIL | Logs record both events separately but not the missing causal link |

---

## Prerequisites

Start the API before running any reproduction commands:

```bash
docker compose up --build
```

Confirm it is running:

```bash
curl http://localhost:8080/health
```

---

## Pattern 1 — Missing Parent Cause

**Rule:** R1 — Reference Integrity
**Finding:** `CML-AUDIT-R1-MISSING_PARENT`
**Severity:** FAIL
**Fixture:** `benchmarks/fixtures/02_missing_parent_reference.json`

### What happens

An action records a `parent_cause` that does not exist anywhere in the log.
The action itself succeeds — the file is opened, the write completes — but
the causal chain cannot be reconstructed because the claimed parent is absent.

### Why ordinary logs miss it

A standard log entry records that the action happened and which process did
it. It does not verify that the claimed `parent_cause` is a real event in
the same log. The broken reference is invisible without causal audit.

### Reproduction

```bash
curl -s -X POST http://localhost:8080/audit \
  -H "Content-Type: application/json" \
  -d '{
    "log": "{\"id\":\"b1\",\"timestamp\":1000000010,\"actor\":{\"pid\":102,\"uid\":1000},\"action\":\"exec\",\"object\":\"/bin/agent\",\"permitted_by\":\"root_event:init\",\"parent_cause\":null}\n{\"id\":\"b2\",\"timestamp\":1000000011,\"actor\":{\"pid\":102,\"uid\":1000},\"action\":\"open\",\"object\":\"/etc/passwd\",\"permitted_by\":\"fs:read\",\"parent_cause\":\"missing\"}",
    "format": "json"
  }'
```

### Expected CML finding

```json
{
    "summary": {"total": 2, "ok": 1, "warnings": 0, "failures": 1, "passed": false},
    "findings": [
        {
            "code": "CML-AUDIT-R1-MISSING_PARENT",
            "severity": "FAIL",
            "record_id": "b2",
            "message": "parent_cause 'missing' does not exist in the log."
        }
    ]
}
```

---

## Pattern 2 — Ambiguous Root Event

**Rule:** R4 — Root Identification
**Finding:** `CML-AUDIT-R4-AMBIGUOUS_ROOT`
**Severity:** WARN
**Fixture:** `benchmarks/fixtures/04_ambiguous_root_authority.json`

### What happens

A root event uses `permitted_by: "root_event"` instead of the required
format `permitted_by: "root_event:<cause>"`. The label looks like a root
declaration but is missing the required separator and cause name. CML cannot
confirm this is a properly declared root event.

### Why ordinary logs miss it

Ordinary logs store the `permitted_by` value as a plain string without
validating its format. A near-miss label like `"root_event"` instead of
`"root_event:system_boot"` passes unnoticed in standard log analysis.

### Reproduction

```bash
curl -s -X POST http://localhost:8080/audit \
  -H "Content-Type: application/json" \
  -d '{
    "log": "{\"id\":\"d1\",\"timestamp\":1000000030,\"actor\":{\"pid\":104,\"uid\":1000},\"action\":\"exec\",\"object\":\"/bin/task\",\"permitted_by\":\"root_event\",\"parent_cause\":null}",
    "format": "json"
  }'
```

### Expected CML finding

```json
{
    "summary": {"total": 1, "ok": 0, "warnings": 1, "failures": 0, "passed": true},
    "findings": [
        {
            "code": "CML-AUDIT-R4-AMBIGUOUS_ROOT",
            "severity": "WARN",
            "record_id": "d1",
            "message": "Near-miss root label: permitted_by='root_event' looks like 'root_event:' but is missing the required separator. Did you mean 'root_event:<cause>'?"
        }
    ]
}
```

---

## Pattern 3 — Unmarked Causal Gap

**Rule:** R2 — Gap Marking
**Finding:** `CML-AUDIT-R2-GAP_NOT_MARKED`
**Severity:** WARN
**Fixture:** `benchmarks/fixtures/03_unmarked_causal_gap.json`

### What happens

An action has `parent_cause: null` but its `permitted_by` is not
`"unobserved_parent"` and not a valid root event label. CML cannot tell
whether this is a legitimate root event or an unmarked break in the chain.

### Why ordinary logs miss it

Ordinary logs do not require a gap to be explicitly acknowledged. An action
with no recorded parent appears as a standalone entry. CML requires that any
intentional break in the causal chain be declared with
`permitted_by: "unobserved_parent"` so reviewers know the gap is deliberate.

### Reproduction

```bash
curl -s -X POST http://localhost:8080/audit \
  -H "Content-Type: application/json" \
  -d '{
    "log": "{\"id\":\"c1\",\"timestamp\":1000000020,\"actor\":{\"pid\":103,\"uid\":1000},\"action\":\"exec\",\"object\":\"/bin/task\",\"permitted_by\":\"some_context\",\"parent_cause\":null}",
    "format": "json"
  }'
```

### Expected CML finding

```json
{
    "summary": {"total": 1, "ok": 0, "warnings": 1, "failures": 0, "passed": true},
    "findings": [
        {
            "code": "CML-AUDIT-R2-GAP_NOT_MARKED",
            "severity": "WARN",
            "record_id": "c1",
            "message": "Causal gap: parent_cause=null but permitted_by='some_context' (expected 'unobserved_parent')."
        }
    ]
}
```

---

## Pattern 4 — Secret Access Without Network Chain

**Rule:** R3 — SECRET → NET_OUT Chain
**Finding:** `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN`
**Severity:** FAIL
**Fixture:** `benchmarks/fixtures/05_secret_to_network_without_lineage.json`

### What happens

A process reads a secret file and later makes an outbound network call.
Both actions succeed individually. But the network action has no causal
link back to the secret read — it appears as a disconnected event. CML
flags this because an outbound connection following a secret access, with
no causal chain connecting them, cannot be verified as authorized.

### Why ordinary logs miss it

Standard logs record the `read` and the `send` as two separate entries.
Nothing in the log structure links them or requires that the network action
be causally authorized by the secret access. CML checks whether the
outbound event traces back through the same causal chain as the preceding
secret read.

### Reproduction

```bash
curl -s -X POST http://localhost:8080/audit \
  -H "Content-Type: application/json" \
  -d '{
    "log": "{\"id\":\"e1\",\"timestamp\":1000000040,\"actor\":{\"pid\":105,\"uid\":1000},\"action\":\"exec\",\"object\":\"/bin/agent\",\"permitted_by\":\"root_event:init\",\"parent_cause\":null}\n{\"id\":\"e2\",\"timestamp\":1000000041,\"actor\":{\"pid\":105,\"uid\":1000},\"action\":\"open\",\"object\":{\"path\":\"/secrets/token.pem\",\"classification\":\"SECRET\"},\"permitted_by\":\"fs:read\",\"parent_cause\":\"e1\"}\n{\"id\":\"e3\",\"timestamp\":1000000042,\"actor\":{\"pid\":105,\"uid\":1000},\"action\":\"send\",\"object\":{\"addr\":\"5.6.7.8\",\"port\":443},\"permitted_by\":\"unobserved_parent\",\"parent_cause\":null}",
    "format": "json"
  }'
```

### Expected CML finding

```json
{
    "summary": {"total": 3, "ok": 2, "warnings": 0, "failures": 1, "passed": false},
    "findings": [
        {
            "code": "CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN",
            "severity": "FAIL",
            "record_id": "e3",
            "message": "NET_OUT 'send' (pid=105) has no causal link to preceding SECRET access(es): ['e2'].",
            "chain_ids": ["e2"]
        }
    ]
}
```

---

## Key Takeaway

In every pattern above, the action itself completed successfully. Ordinary
logs would show normal operational output. CML surfaces the causal
invalidity because it checks not just *what happened* but *whether the
action had a valid permission and responsibility lineage*.

> A system can be functionally correct while being causally invalid.
