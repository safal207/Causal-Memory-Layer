# Contributing to CML

Welcome. This guide is for everyone who wants to contribute —
whether you're fixing a typo, adding an example log, improving the CLI, extending the VS Code extension,
or proposing changes to the specification.

CML is a small, principled project. The most important thing a contributor can do is
**preserve the clarity of what CML is and is not**.

---

## First: understand the invariant

Before writing any code, read this once:

> **A system may be functionally correct while being causally invalid.**

This is the founding statement. Every contribution should strengthen it, not dilute it.
If a change makes CML do more things but makes that sentence less true, the change is wrong.

---

## What CML is NOT building

Read the non-goals before you propose anything:

- Not a security enforcement engine
- Not a policy system (CML records *why*, does not judge *if it should*)
- Not a performance-optimized tracer
- Not tied to any specific OS, language, or runtime

If your idea adds one of these, it's out of scope.
Open an issue to discuss before implementing — scope questions are always worth discussing.

---

## Repository layout

```
Causal-Memory-Layer/
│
├── vcml/                     ← THE SPECIFICATION (start here)
│   ├── README.md             ← What vCML is and how it lives in a system
│   ├── FORMAT.md             ← Causal record format (fields, types, constraints)
│   ├── audit.md              ← Audit rules R1–R4 (normative)
│   ├── CTAG.md               ← Causal Tag semantics
│   ├── multi_boundary.md     ← Multi-boundary memory (exec + fs + net)
│   └── linux-ebpf/           ← eBPF reference skeleton (not production code)
│
├── cli/                      ← Python CLI (implements vcml/audit.md)
│   ├── main.py               ← Entry point: `audit` and `chain` commands
│   ├── audit.py              ← Rule engine: R1, R2, R3, R4
│   └── chain.py              ← Chain reconstruction
│
├── integrations/
│   └── vscode-cml/           ← VS Code extension
│       ├── src/
│       │   ├── extension.ts  ← Activation, command registration
│       │   ├── commands/     ← `audit`, `chain`, `auditExample` commands
│       │   ├── core/         ← CLI invocation, result parsing
│       │   └── views/        ← Audit results webview panel
│       └── package.json
│
├── examples/                 ← Reference JSONL logs
│   ├── secret_to_net_log.jsonl   ← Canonical R3 violation + valid counterpart
│   └── exec_causal_log.jsonl     ← Clean exec chain
│
└── docs/wiki/                ← Wiki pages (mirrors GitHub Wiki)
```

**The canonical source of truth is always `vcml/`.**
The CLI and extension implement its rules — they do not invent their own.

---

## Where to start

### If you want to contribute to the specification (`vcml/`)

- Read all of `vcml/` first (it's short)
- Read `DECISION_CODES.md` — every non-obvious decision has a code explaining why
- Open an issue before changing normative rules (R1–R4 in `audit.md`)
- Spec changes should be small and justified — one rule, one addition at a time

### If you want to contribute to the CLI (`cli/`)

```bash
# Run all examples to verify nothing is broken
python3 -m cli.main audit examples/secret_to_net_log.jsonl
python3 -m cli.main audit examples/exec_causal_log.jsonl
python3 -m cli.main chain examples/secret_to_net_log.jsonl b3
```

- The CLI has no test framework yet — the examples are the tests
- `audit.py` maps directly to rules in `vcml/audit.md`: keep that alignment explicit
- Rule codes (`CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN`) must match the spec exactly

### If you want to contribute to the VS Code extension

```bash
cd integrations/vscode-cml
npm install
npm run build      # or: npm run watch for incremental builds
```

Press **F5** in VS Code to launch the Extension Development Host.

Key files:
- `src/extension.ts` — activates the extension, registers all commands
- `src/commands/` — one file per command (`audit.ts`, `chain.ts`, `auditExample.ts`)
- `src/core/cliRunner.ts` — spawns the Python CLI, parses stdout
- `src/views/auditPanel.ts` — the webview panel (HTML/CSS rendered in VS Code)

The extension is a thin wrapper. It calls the CLI and displays results.
It does not implement any audit logic itself.

### If you want to add example logs

- Add new `.jsonl` files to `examples/`
- Follow the format in `vcml/FORMAT.md`
- Each record must be valid JSON on a single line
- Include a companion `.md` file explaining what the log demonstrates (see `examples/secret_to_net_explain.md`)

### If you want to improve the wiki / docs

- Pages live in `docs/wiki/` — edit them there and open a PR
- Page names match their GitHub Wiki counterparts exactly

---

## Code style

**Python (CLI):**
- Standard library only — no external dependencies
- Functions are small and named after what they check (e.g. `check_r3_secret_net`)
- Audit rule logic lives in `audit.py`, not in `main.py`
- Output format (`text` vs `json`) is handled only in `main.py`

**TypeScript (extension):**
- `npm run build` must succeed with no errors
- The extension does not bundle a Python interpreter — it uses whatever `python3` is on PATH
- Webview HTML is in `auditPanel.ts` as a template string (no separate HTML files)

---

## Commit messages

Keep them short and honest:

```
cli: fix R3 check missing parent chain traversal
vcml: clarify gap semantics in audit.md (R2 vs R4)
extension: add chain view for selected record
examples: add multi-boundary scenario with clean chain
docs: add Contributing wiki page
```

Prefix with the affected area: `cli`, `vcml`, `extension`, `examples`, `docs`.

---

## Opening issues

Before opening an issue:

1. Check that it's not a non-goal (list above)
2. For spec changes — describe the problem, not the solution. Let the discussion find the right answer.
3. For bugs — include: the exact command, the log file content (or a minimal reproduction), the actual output, the expected output

Label suggestions:
- `spec` — touches `vcml/`
- `cli` — touches `cli/`
- `extension` — touches `integrations/vscode-cml/`
- `question` — not a bug, just something unclear
- `good first issue` — well-scoped, doesn't require deep spec knowledge

---

## What makes a good contribution

In order of importance:

1. **Preserves the core invariant** — functional correctness ≠ causal validity
2. **Keeps CLI and spec aligned** — rule codes, semantics, edge cases must match `vcml/audit.md`
3. **Is small** — one thing at a time. The right amount of complexity is the minimum needed.
4. **Has a clear example** — a new audit rule without an example log demonstrating it is incomplete
5. **Doesn't add non-goals** — see above

---

## Roadmap context

Current version: **v0.2** — specification-first, CLI + VS Code extension as first implementations.

What's coming next (see `ROADMAP.md`):
- **v0.3** — exec boundary with a real eBPF hook
- **v0.4** — CTAG (causal tags) validation
- **v0.5** — multi-boundary memory (already specified, needs implementation)

If you want to work on v0.3+ features, open an issue to coordinate — these are larger, architectural contributions that need discussion before implementation.

---

## Thank you

CML is an unusual project — it's specification-first, slow by design, and deliberately small.
If that resonates with you, you're exactly the right kind of contributor.
