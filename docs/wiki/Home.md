# Causal Memory Layer — Wiki

> **"A system may be functionally correct while being causally invalid."**

Welcome. This wiki is for everyone who wants to understand, use, or extend CML —
whether you're a developer, a curious reader, or someone looking to contribute.

---

## What is CML?

The **Causal Memory Layer** is an immutable record of *why* a state change was permitted to happen.

Most systems record **what** happened and **when**. CML records **why** — linking every action
back to the intent, authorization, and causal context that made it possible.

It is not a security product, not a policy engine, not a transport layer.
It is a **memory layer** — a read-only audit trail that tells you whether a causal chain is coherent.

---

## Who is this wiki for?

| I am... | Start here |
|---|---|
| New to CML, just curious | [Concepts](Concepts) — what causal validity means and why it matters |
| Developer, want to try it | [Getting Started](Getting-Started) — install, run, audit your first log |
| Want to see it in action | [Demo](Demo) — step-by-step terminal walkthrough |
| Want the strongest first audit demo | [Demo Package: Causal Invalidity](../demos/secret_to_network_causal_invalid/README.md) — secret→network that succeeds functionally but fails causally |
| Want real-world scenarios | [Scenarios](Scenarios) — concrete use cases and what CML shows |
| Want to contribute | [Contributing](Contributing) — architecture, conventions, where to start |

---

## Quick orientation

```
Causal-Memory-Layer/
├── vcml/           Specification: format, audit rules, CTAG semantics
├── cli/            Python CLI — audit and chain inspection
├── examples/       Sample .jsonl causal logs
└── integrations/
    └── vscode-cml/ VS Code extension (audit panel, diagnostics, chain view)
```

The canonical source of truth is always `vcml/`. The CLI and extension implement its semantics —
they do not add or change any rules.

---

## Core concepts at a glance

**Causal record** — a single boundary event (exec, read, connect, send…) with:
- `id` — unique identifier
- `action` — what boundary was crossed
- `object` — what was affected
- `actor` — who did it (pid/uid)
- `permitted_by` — what capability or record permitted this
- `parent_cause` — the id of the record that caused this one

**Causal chain** — a path of `parent_cause` links from a terminal event back to a root.

**Causal gap** — a record with `parent_cause: null` that is neither a root event nor explicitly marked as `unobserved_parent`.

**Audit** — checking whether all rules R1–R4 hold across a log. Read-only. Never blocks anything.

---

## Audit rules (v0.5.1)

| Rule | What it checks | Severity |
|---|---|---|
| R1 | `parent_cause` references a real record | FAIL |
| R2 | Gaps are explicitly marked as `unobserved_parent` | WARN |
| R3 | NET_OUT after a SECRET read has a causal link back to that read | FAIL |
| R4 | `parent_cause: null` is either a root event or a marked gap | WARN |

---

## Status

CML is at **v0.2** — specification-first. The CLI and VS Code extension are the first working implementations.

See [`ROADMAP.md`](../ROADMAP.md) for the full roadmap (v0.3 → exec boundary, v0.5 → multi-boundary memory, …).
