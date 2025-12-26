# vCML — Virtual Causal Memory Layer

vCML is a **virtual, OS-adjacent reference implementation** of the Causal Memory Layer (CML).

Its purpose is to demonstrate how *causal memory* — memory of **why actions were permitted to happen** —
can exist at system boundaries, independently of transport, execution, or storage mechanisms.

vCML is not a product, not a security system, and not a policy engine.
It is a **semantic prototype**.

---

## What vCML Is

vCML records **causal permission**, not execution results.

Each recorded action answers the question:

> Why was this action **permitted** to happen?

This includes:
- who initiated the action,
- what boundary was crossed,
- what object was affected,
- which permission, capability, or prior cause allowed it,
- and how this action links to previous causal context.

vCML treats causality as **first-class data**.

---

## What vCML Is Not

vCML deliberately does **not**:
- block or deny system actions,
- enforce security policies,
- optimize for performance,
- replace tracing, logging, or observability tools,
- define storage backends or databases.

A system may be functionally correct while being causally invalid.
vCML exists to make such cases observable.

---

## Why OS Boundaries

Operating system boundaries (syscalls, process creation, file and network access)
are natural **causal checkpoints**:

- intent becomes execution,
- permission becomes effect,
- abstract decisions become irreversible actions.

vCML attaches causal memory precisely at these boundaries.

---

## Relationship to CML

Causal Memory Layer (CML) defines:
- semantics,
- invariants,
- meaning of causal memory.

vCML demonstrates:
- how those semantics can live in a real system,
- without collapsing into implementation-specific assumptions.

vCML is a reference path — not the only one.

---

## Current Status

vCML is intentionally minimal.
Early versions focus on:
- causal record format,
- clear boundaries,
- append-only causal journaling.

Execution, optimization, and enforcement are explicitly out of scope.
