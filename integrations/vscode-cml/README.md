# CML — VS Code Extension (MVP)

A minimal VS Code integration for the [Causal Memory Layer](../../README.md).
Open a `.jsonl` causal log and audit it for causal validity — directly in your editor.

> **Tone:** This is an audit viewer, not a security scanner. It tells you whether a recorded causal chain is coherent. It never blocks, enforces, or modifies anything.

---

## What it does

| Command | What happens |
|---|---|
| **CML: Audit Current Log** | Runs the CML audit against the `.jsonl` file in the active editor. Shows a summary panel and highlights violations in the Problems panel. |
| **CML: Show Chain for Selected Record** | Place your cursor on any JSONL line with an `id` field and run this command. The causal chain (from root to that record) is displayed in the CML Chain output channel. |
| **CML: Audit Example Log** | Pick `secret_to_net_log.jsonl` or `exec_causal_log.jsonl` from a quick-pick menu. The file opens and is audited automatically — ideal for onboarding and demos. |

Commands are also accessible from the right-click context menu inside a `.jsonl` file.

---

## How it works

The extension is a **thin UI layer** over the Python CLI at `cli/`. It spawns:

```
python3 -m cli.main audit  <file.jsonl> --format json
python3 -m cli.main chain  <file.jsonl> <record_id>
```

No audit logic is reimplemented in TypeScript. The Python CLI is the single source of truth for all CML semantics (rules R1–R4, chain reconstruction).

---

## Setup

### Prerequisites

- **Python 3.9+** with `python3` or `python` in your PATH
- The **Causal-Memory-Layer repository** open as your VS Code workspace root

### Install extension dependencies

```bash
cd integrations/vscode-cml
npm install
```

### Build (compile TypeScript → JavaScript)

```bash
npm run build
# or to watch for changes:
npm run watch
```

### Run in VS Code (development)

1. Open the `Causal-Memory-Layer` folder in VS Code
2. Press **F5** (or run _Debug: Start Debugging_)
3. A new VS Code window opens with the extension loaded
4. Open `examples/secret_to_net_log.jsonl`
5. Press `Ctrl+Shift+P` → **CML: Audit Current Log**

---

## Demo scenario

### Validate the R3 violation

1. Open `examples/secret_to_net_log.jsonl`
2. Run **CML: Audit Current Log**
3. The audit panel opens showing **1 FAIL** (`CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN`)
4. Line 8 (record `b3`) gets an error diagnostic in the Problems panel
5. Place cursor on line 8 and run **CML: Show Chain for Selected Record**
6. The CML Chain output channel shows:
   - `b3` has `parent_cause=null` (gap)
   - The unlinked SECRET access `b2` (`read /secrets/token`) is flagged as missing from the chain

### Validate a clean log

1. Run **CML: Audit Example Log** → pick `exec_causal_log.jsonl`
2. Audit passes with 2 OK, 0 WARN, 0 FAIL

---

## Audit rules (v0.5.1)

| Rule | Code | Severity | Description |
|---|---|---|---|
| R1 | `CML-AUDIT-R1-MISSING_PARENT` | FAIL | `parent_cause` points to a record that doesn't exist |
| R2 | `CML-AUDIT-R2-GAP_NOT_MARKED` | WARN | `parent_cause=null` without `unobserved_parent` or `root_event:` label |
| R3 | `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN` | FAIL | NET_OUT after a SECRET access with no causal link back to that access |
| R4 | `CML-AUDIT-R4-AMBIGUOUS_ROOT` | WARN | `parent_cause=null` with an unrecognized `permitted_by` value |

See [`vcml/audit.md`](../../vcml/audit.md) for the full specification.

---

## Limitations (MVP)

- **Read-only.** The extension never modifies logs, blocks processes, or enforces policy.
- **Local CLI only.** No hosted API. The Python CLI must be runnable from the workspace root.
- **Single-file audit.** Multi-file chain reconstruction is not yet supported.
- **No marketplace packaging.** Install manually via F5 / Extension Development Host.
- **No Cursor integration.** Out of scope for this MVP.
- **No telemetry.** Nothing is sent anywhere.

---

## File structure

```
integrations/vscode-cml/
├── package.json          — extension manifest and npm scripts
├── tsconfig.json         — TypeScript compiler config
├── README.md             — this file
└── src/
    ├── extension.ts      — activation, command registration
    ├── commands/
    │   ├── auditCurrentLog.ts   — "CML: Audit Current Log"
    │   ├── showChain.ts         — "CML: Show Chain for Selected Record"
    │   └── auditExample.ts      — "CML: Audit Example Log"
    ├── core/
    │   ├── cli.ts         — spawns Python CLI, typed result interfaces
    │   ├── jsonl.ts       — JSONL line parsing, id→line mapping
    │   └── diagnostics.ts — maps findings to VS Code diagnostics
    └── views/
        └── auditPanel.ts  — webview panel showing audit summary
```

The Python CLI lives at `cli/` in the repository root:

```
cli/
├── __init__.py
├── main.py    — argparse entry point (audit / chain subcommands)
├── audit.py   — R1–R4 rule engine
└── chain.py   — causal chain reconstruction
```

---

## Follow-up ideas

- Status bar item showing latest audit result for the active file
- Hover provider showing finding summary when hovering a JSONL line
- "Open example log" command without auditing immediately
- Refresh button in the audit panel
- Multi-file chain reconstruction across log archives
