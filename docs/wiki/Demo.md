# Demo — Live Walkthrough

A step-by-step terminal session showing everything CML can do right now.
Copy-paste any block to follow along.

**Prerequisites:** Python 3.9+, the repository cloned locally.

---

## Setup

```bash
git clone https://github.com/safal207/Causal-Memory-Layer.git
cd Causal-Memory-Layer
```

That's it. No pip installs.

---

## Part 1 — Find the causal violation

### 1.1 Look at the log

```bash
cat examples/secret_to_net_log.jsonl
```

You'll see 8 records: two parallel stories (`a`-series and `b`-series), each involving
a process that reads a secret and sends data to the network.

They look similar. CML will show they are fundamentally different.

### 1.2 Audit the log

```bash
python3 -m cli.main audit examples/secret_to_net_log.jsonl
```

```
CML Audit: FAILED
  File : examples/secret_to_net_log.jsonl
  Total: 8  OK: 7  WARN: 0  FAIL: 1
  [FAIL] CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN @ b3 (line 8)
        NET_OUT (send to 198.51.100.45:8443) has no causal chain back to SECRET access (b2 read /secrets/token)
```

One record fails. Record `b3` — the network send in the `b`-series.

### 1.3 Get the full JSON output

```bash
python3 -m cli.main audit examples/secret_to_net_log.jsonl --format json
```

The JSON output is what the VS Code extension consumes. It includes per-record findings
with line numbers, so editors can attach diagnostics precisely.

---

## Part 2 — Inspect the broken chain

### 2.1 Trace b3's chain

```bash
python3 -m cli.main chain examples/secret_to_net_log.jsonl b3
```

```json
{
  "target_id": "b3",
  "chain": [
    {
      "id": "b3",
      "action": "send",
      "object": { "addr": "198.51.100.45", "port": 8443, "bytes": 1024 },
      "actor": { "pid": 5220, "comm": "uploader" },
      "permitted_by": "unobserved_parent",
      "parent_cause": null
    }
  ],
  "has_gap": true,
  "gap_note": "Chain has a gap at 'b3': parent is unobserved (permitted_by: unobserved_parent)",
  "r3_context": {
    "secret_record": {
      "id": "b2",
      "action": "read",
      "object": { "path": "/secrets/token", "classification": "SECRET" },
      "actor": { "pid": 5220 }
    },
    "note": "SECRET access (b2 read /secrets/token) by same process is NOT causally linked to this NET_OUT record"
  }
}
```

The chain is just `[b3]`. It starts with a gap — `parent_cause: null`.
The `r3_context` shows what's missing: `b2` (the secret read) is in the same process
but has no causal path to `b3`.

### 2.2 Compare with the valid chain

```bash
python3 -m cli.main chain examples/secret_to_net_log.jsonl a5
```

The chain for `a5` (the send in the *valid* story) traces back through:
`a5 → a3 (secret read) → a2 (secret open) → a1 (exec, root)`

Notice `a5`'s chain *includes* the secret read (`a3`). That's why R3 passes for `a5`.

---

## Part 3 — Validate a clean log

```bash
python3 -m cli.main audit examples/exec_causal_log.jsonl
```

```
CML Audit: PASSED
  File : examples/exec_causal_log.jsonl
  Total: 2  OK: 2  WARN: 0  FAIL: 0
```

No violations. A simple exec chain: `bash → ls`, with the parent process context
properly recorded.

```bash
python3 -m cli.main chain examples/exec_causal_log.jsonl 550e8400-e29b-41d4-a716-446655440001
```

The chain shows `ls` caused by `bash`. The root has `permitted_by: "unobserved_parent"` —
a valid gap marker meaning "bash started before we began observing."

---

## Part 4 — Write your own log

Let's create a log that passes, then break it deliberately.

### 4.1 Write a valid log

```bash
cat > /tmp/myapp.jsonl << 'EOF'
{"id":"m1","timestamp":1700000001,"actor":{"pid":1000,"uid":100},"action":"exec","object":"/usr/bin/myapp","permitted_by":"root_event:init","parent_cause":null}
{"id":"m2","timestamp":1700000002,"actor":{"pid":1000,"uid":100},"action":"read","object":{"path":"/secrets/db_pass","classification":"SECRET"},"permitted_by":"fs:read","parent_cause":"m1"}
{"id":"m3","timestamp":1700000003,"actor":{"pid":1000,"uid":100},"action":"connect","object":{"addr":"db.internal","port":5432},"permitted_by":"net:egress","parent_cause":"m2"}
{"id":"m4","timestamp":1700000004,"actor":{"pid":1000,"uid":100},"action":"send","object":{"addr":"db.internal","port":5432,"bytes":128},"permitted_by":"net:egress","parent_cause":"m2"}
EOF

python3 -m cli.main audit /tmp/myapp.jsonl
```

```
CML Audit: PASSED
  Total: 4  OK: 4  WARN: 0  FAIL: 0
```

All four records pass. The send (`m4`) is causally downstream of the secret read (`m2`).

### 4.2 Break the causal link

Now sever `m4`'s connection to the chain:

```bash
cat > /tmp/myapp_broken.jsonl << 'EOF'
{"id":"m1","timestamp":1700000001,"actor":{"pid":1000,"uid":100},"action":"exec","object":"/usr/bin/myapp","permitted_by":"root_event:init","parent_cause":null}
{"id":"m2","timestamp":1700000002,"actor":{"pid":1000,"uid":100},"action":"read","object":{"path":"/secrets/db_pass","classification":"SECRET"},"permitted_by":"fs:read","parent_cause":"m1"}
{"id":"m3","timestamp":1700000003,"actor":{"pid":1000,"uid":100},"action":"connect","object":{"addr":"db.internal","port":5432},"permitted_by":"net:egress","parent_cause":"m2"}
{"id":"m4","timestamp":1700000004,"actor":{"pid":1000,"uid":100},"action":"send","object":{"addr":"db.internal","port":5432,"bytes":128},"permitted_by":"unobserved_parent","parent_cause":null}
EOF

python3 -m cli.main audit /tmp/myapp_broken.jsonl
```

```
CML Audit: FAILED
  Total: 4  OK: 3  WARN: 0  FAIL: 1
  [FAIL] CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN @ m4 (line 4)
        NET_OUT (send to db.internal:5432) has no causal chain back to SECRET access (m2 read /secrets/db_pass)
```

The only change was setting `m4`'s `parent_cause` to null. The system is now causally invalid.

---

## Part 5 — VS Code (bonus)

If you have VS Code and Node.js installed:

```bash
cd integrations/vscode-cml
npm install
npm run build
cd ../..
code .
```

Press F5 → open `examples/secret_to_net_log.jsonl` → `Ctrl+Shift+P` → **CML: Audit Current Log**.

You'll see line 8 highlighted with a red underline (error diagnostic), a summary panel on the right,
and the finding in the Problems panel.

Put your cursor on line 8 and run **CML: Show Chain for Selected Record** to see the chain
in the output channel.

---

## What you've seen

| Action | Result |
|---|---|
| Audit a log with a causal gap | Found 1 FAIL (R3) on record `b3` |
| Inspect the broken chain | Chain starts at `b3` with `parent_cause=null`; `b2` (SECRET) is unlinked |
| Audit a valid chain | 2 OK, passed cleanly |
| Write a valid log from scratch | 4 OK, passed |
| Sever one `parent_cause` link | Immediately triggers R3 FAIL |

**Key takeaway:** CML makes the difference between "a send happened after a secret read"
and "the send happened *because of* the secret read" visible and verifiable.
