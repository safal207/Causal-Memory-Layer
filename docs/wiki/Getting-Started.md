# Getting Started

This page gets you from zero to a working audit in under 5 minutes.

---

## Prerequisites

| Requirement | Minimum version | Check |
|---|---|---|
| Python | 3.9+ | `python3 --version` |
| Git | any | `git --version` |
| VS Code *(optional)* | 1.85+ | — |
| Node.js + npm *(for extension)* | Node 18+ | `node --version` |

No pip packages required. The CLI uses only the Python standard library.

---

## 1. Clone the repository

```bash
git clone https://github.com/safal207/Causal-Memory-Layer.git
cd Causal-Memory-Layer
```

---

## 2. Try the CLI

### Audit a log

```bash
python3 -m cli.main audit examples/secret_to_net_log.jsonl
```

Expected output:

```
CML Audit: FAILED
  File : examples/secret_to_net_log.jsonl
  Total: 8  OK: 7  WARN: 0  FAIL: 1
  [FAIL] CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN @ b3 (line 8)
        NET_OUT (send to 198.51.100.45:8443) has no causal chain back to SECRET access (b2 read /secrets/token)
```

```bash
python3 -m cli.main audit examples/exec_causal_log.jsonl
```

Expected output:

```
CML Audit: PASSED
  File : examples/exec_causal_log.jsonl
  Total: 2  OK: 2  WARN: 0  FAIL: 0
```

### Inspect a causal chain

```bash
python3 -m cli.main chain examples/secret_to_net_log.jsonl b3
```

This reconstructs the causal chain ending at record `b3` and shows where the chain breaks
and which SECRET access is missing from it.

### Get JSON output (for scripting)

```bash
python3 -m cli.main audit examples/secret_to_net_log.jsonl --format json
```

---

## 3. VS Code Extension (optional)

### Install dependencies

```bash
cd integrations/vscode-cml
npm install
npm run build
```

### Launch in VS Code

1. Open the repository root in VS Code:
   ```bash
   code .
   ```
2. Press **F5** — a new Extension Development Host window opens with the extension active
3. In that window, open `examples/secret_to_net_log.jsonl`
4. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) → **CML: Audit Current Log**

You should see:
- A webview panel on the right with the audit summary (1 FAIL)
- Line 8 underlined in the editor with an error diagnostic
- The finding in the Problems panel (`View → Problems`)

### Try chain inspection

1. Click on line 8 (record `b3`) in the log file
2. `Ctrl+Shift+P` → **CML: Show Chain for Selected Record**
3. The **CML Chain** output channel opens showing the gap and the missing SECRET link

### Try the demo quick-pick

`Ctrl+Shift+P` → **CML: Audit Example Log** → pick either example — the file opens and is audited automatically.

---

## 4. Audit your own log

Create a `.jsonl` file where each line is a valid causal record:

```jsonl
{"id":"r1","timestamp":1700000001,"actor":{"pid":100,"uid":1000},"action":"exec","object":"/usr/bin/myapp","permitted_by":"root_event:init","parent_cause":null}
{"id":"r2","timestamp":1700000002,"actor":{"pid":100,"uid":1000},"action":"read","object":{"path":"/secrets/db_password","classification":"SECRET"},"permitted_by":"fs:read","parent_cause":"r1"}
{"id":"r3","timestamp":1700000003,"actor":{"pid":100,"uid":1000},"action":"connect","object":{"addr":"10.0.0.1","port":5432},"permitted_by":"net:egress","parent_cause":"r2"}
```

Then audit it:

```bash
python3 -m cli.main audit your_log.jsonl
```

Record `r3` will pass R3 because its `parent_cause` chain includes `r2` (the SECRET read).

---

## CLI reference

```
python3 -m cli.main <command> [options]

Commands:
  audit <file>              Audit a JSONL causal log against CML rules R1–R4
    --format json|text      Output format (default: text)

  chain <file> <record_id>  Reconstruct causal chain for a record (always JSON)
```

---

## What each audit finding means

| Code | Severity | Meaning |
|---|---|---|
| `CML-AUDIT-R1-MISSING_PARENT` | FAIL | A `parent_cause` points to a record that isn't in this log |
| `CML-AUDIT-R2-GAP_NOT_MARKED` | WARN | A null `parent_cause` isn't labeled as `unobserved_parent` |
| `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN` | FAIL | Data left a machine after a secret was read, with no causal link connecting them |
| `CML-AUDIT-R4-AMBIGUOUS_ROOT` | WARN | A null `parent_cause` has an unrecognized `permitted_by` value |

A **FAIL** means the log is causally invalid — not that something malicious happened.
CML makes no judgement about intent.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'cli'`**
Run the command from the repository root, not from inside the `cli/` directory.

**`python3: command not found`**
Try `python` instead of `python3`. Both work.

**VS Code extension: "CML CLI not found"**
Make sure the **Causal-Memory-Layer** folder is your workspace root (the folder VS Code has open),
not a subfolder of it.
