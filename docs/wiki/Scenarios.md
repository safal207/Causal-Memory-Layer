# Scenarios — CML in Practice

Concrete use cases showing what CML records, what the audit finds,
and what it means. Each scenario includes a sample log and the expected audit outcome.

---

## Scenario 1: Secret leaks to network (no causal link)

**Context:** An upload service reads a token from `/secrets/token` and sends data to an external server. The causal link between the read and the send is missing from the log.

**Why CML flags this:** Two events happened in the same process — a SECRET read and a NET_OUT. Without a `parent_cause` link, CML cannot confirm that the send was a *consequence* of the read. It could be a coincidence. It could be a bug. It could be intentional exfiltration. CML doesn't decide — it just marks the chain as causally invalid.

**Sample log:** `examples/secret_to_net_log.jsonl` (records `b1`–`b3`)

```jsonl
{"id":"b1","actor":{"pid":5220},"action":"exec","object":"/usr/bin/uploader","permitted_by":"root_event:init","parent_cause":null}
{"id":"b2","actor":{"pid":5220},"action":"read","object":{"path":"/secrets/token","classification":"SECRET"},"permitted_by":"fs:read","parent_cause":"b1"}
{"id":"b3","actor":{"pid":5220},"action":"send","object":{"addr":"198.51.100.45","port":8443},"permitted_by":"unobserved_parent","parent_cause":null}
```

**Audit result:**
```
[FAIL] CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN @ b3
       NET_OUT (send to 198.51.100.45:8443) has no causal chain back to SECRET access (b2 read /secrets/token)
```

**What the chain shows:**
```
[b3] send to 198.51.100.45:8443
     parent_cause: null  ← CAUSAL GAP

Unlinked SECRET access:
     [b2] read /secrets/token  (same process, not in chain)
```

**Compare with:** Records `a1`–`a5` in the same file show the same pattern done *correctly*: the send's `parent_cause` chain includes the secret read. The audit passes for those records.

---

## Scenario 2: Clean exec chain

**Context:** A shell process forks a child process (`ls`). The child's causal origin is traceable to the parent.

**Sample log:** `examples/exec_causal_log.jsonl`

```jsonl
{"id":"550e...000","actor":{"pid":2000},"action":"exec","object":"/bin/bash","permitted_by":"unobserved_parent","parent_cause":null}
{"id":"550e...001","actor":{"pid":2001},"action":"exec","object":"/usr/bin/ls","permitted_by":"parent_process_context","parent_cause":"550e...000"}
```

**Audit result:**
```
CML Audit: PASSED
  Total: 2  OK: 2  WARN: 0  FAIL: 0
```

**Notes:**
- Record `000` has `parent_cause: null` with `permitted_by: "unobserved_parent"` — this is a valid gap marker. The bash process started before observation began.
- Record `001` has a proper `parent_cause` linking it to bash.
- No secrets involved, no NET_OUT — R3 does not apply.

---

## Scenario 3: Missing parent reference (R1)

**Context:** A log where a record references a `parent_cause` id that doesn't exist in the file. This happens when logs are truncated, split across files, or records are deleted.

**Sample log:**

```jsonl
{"id":"x1","actor":{"pid":100},"action":"exec","object":"/usr/bin/app","permitted_by":"root_event:init","parent_cause":null}
{"id":"x2","actor":{"pid":100},"action":"read","object":"/config/settings.json","permitted_by":"fs:read","parent_cause":"MISSING_ID"}
```

**Audit result:**
```
[FAIL] CML-AUDIT-R1-MISSING_PARENT @ x2
       parent_cause 'MISSING_ID' references a record that does not exist in this log
```

**What this means:** The log is incomplete. You can't reconstruct the causal chain for `x2` — its origin is unknown. This is a reference integrity failure, not a semantic one.

---

## Scenario 4: Unmarked gap (R2 + R4)

**Context:** A record has `parent_cause: null` but the `permitted_by` field is neither a `root_event:` label nor `unobserved_parent`. CML can't tell if this is a root event or a gap.

**Sample log:**

```jsonl
{"id":"y1","actor":{"pid":300},"action":"exec","object":"/usr/bin/agent","permitted_by":"some_scheduler","parent_cause":null}
```

**Audit result:**
```
[WARN] CML-AUDIT-R2-GAP_NOT_MARKED @ y1
       parent_cause is null but permitted_by ('some_scheduler') is neither 'unobserved_parent' nor a 'root_event:' label

[WARN] CML-AUDIT-R4-AMBIGUOUS_ROOT @ y1
       Record has parent_cause=null but is neither labeled as root_event nor as unobserved_parent
```

**How to fix:**
- If this is a root event (no actual parent): `"permitted_by": "root_event:scheduler"`
- If the parent exists but wasn't captured: `"permitted_by": "unobserved_parent"`

---

## Scenario 5: Multi-step data pipeline (valid)

**Context:** A data pipeline reads credentials, connects to a database, queries data, and sends a report. All steps are causally linked.

**Log:**

```jsonl
{"id":"p1","actor":{"pid":9000},"action":"exec","object":"/usr/bin/pipeline","permitted_by":"root_event:cron","parent_cause":null}
{"id":"p2","actor":{"pid":9000},"action":"read","object":{"path":"/secrets/db_password","classification":"SECRET"},"permitted_by":"fs:read","parent_cause":"p1"}
{"id":"p3","actor":{"pid":9000},"action":"connect","object":{"addr":"10.0.1.5","port":5432},"permitted_by":"net:egress","parent_cause":"p2"}
{"id":"p4","actor":{"pid":9000},"action":"read","object":"/var/data/report.csv","permitted_by":"fs:read","parent_cause":"p3"}
{"id":"p5","actor":{"pid":9000},"action":"send","object":{"addr":"dashboard.internal","port":443},"permitted_by":"net:egress","parent_cause":"p4"}
```

**Audit result:** PASSED — 5 OK, 0 WARN, 0 FAIL

**Chain for p5:**
```
[p1] exec /usr/bin/pipeline  (root)
      │
[p2] read /secrets/db_password  (SECRET)
      │
[p3] connect 10.0.1.5:5432
      │
[p4] read /var/data/report.csv
      │
[p5] send to dashboard.internal:443
```

R3 passes because `p5`'s `parent_cause` chain includes `p2` (the SECRET read).
The data pipeline can prove its network send is causally downstream of the secret access.

---

## Scenario 6: Same process, two independent flows (split correctly)

**Context:** A process performs two independent tasks: fetches a secret for one operation, and sends unrelated telemetry. The telemetry has its own causal chain that does NOT include the secret read.

**Log:**

```jsonl
{"id":"q1","actor":{"pid":7000},"action":"exec","object":"/usr/bin/agent","permitted_by":"root_event:init","parent_cause":null}
{"id":"q2","actor":{"pid":7000},"action":"read","object":{"path":"/secrets/api_key","classification":"SECRET"},"permitted_by":"fs:read","parent_cause":"q1"}
{"id":"q3","actor":{"pid":7000},"action":"connect","object":{"addr":"api.example.com","port":443},"permitted_by":"net:egress","parent_cause":"q2"}
{"id":"q4","actor":{"pid":7000},"action":"send","object":{"addr":"api.example.com","port":443},"permitted_by":"net:egress","parent_cause":"q2"}
{"id":"q5","actor":{"pid":7000},"action":"read","object":"/proc/uptime","permitted_by":"fs:read","parent_cause":"q1"}
{"id":"q6","actor":{"pid":7000},"action":"send","object":{"addr":"telemetry.internal","port":9090},"permitted_by":"net:egress","parent_cause":"q5"}
```

**Audit result:** PASSED — 6 OK, 0 WARN, 0 FAIL

- `q4` (send to api.example.com) → parent chain includes `q2` (SECRET read) ✓ R3 passes
- `q6` (send to telemetry.internal) → parent chain is `q5 → q1`, does NOT include `q2`

**Wait — why does R3 not flag q6?**

Because `q6`'s parent chain (`q5 → q1`) does not include the SECRET read. CML checks whether a NET_OUT's *own causal chain* leads back to a SECRET access. `q6` can prove its origin is `q5` (reading `/proc/uptime`), not the secret. The chain is clean.

This is the important nuance: R3 only fires when the process has accessed a SECRET *and* the NET_OUT's chain doesn't include that access. If the send has an independent causal chain, it passes.

---

## Summary table

| Scenario | Audit outcome | Rule |
|---|---|---|
| Missing causal link: SECRET → NET_OUT | FAIL | R3 |
| Clean exec chain with marked gap | PASS | — |
| Truncated log / missing parent record | FAIL | R1 |
| Null parent with unlabeled permitted_by | WARN | R2, R4 |
| Full pipeline with proper chain | PASS | — |
| Independent flows in same process | PASS | — |
