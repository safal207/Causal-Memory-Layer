# vCML Linux eBPF Reference Path

This directory contains a **reference path** for implementing vCML
using Linux and eBPF.

It is not the only possible implementation.
It is chosen because Linux is the dominant platform for:
- servers,
- cloud infrastructure,
- containers,
- open-source systems.

---

## Why eBPF

eBPF allows OS-adjacent instrumentation:
- without modifying kernel source,
- without heavy kernel modules,
- with precise access to syscall boundaries.

This makes it suitable for attaching **causal memory hooks**
at points where intent becomes execution.

---

## Initial Boundary: exec

The first targeted boundary is:

- **process execution (exec)**

Reasons:
- simplest causal boundary,
- clear parent-child relationships,
- immediate visibility of causal chains,
- minimal ambiguity.

Future boundaries may include:
- file access,
- network connections,
- inter-process communication.

---

## Structure

linux-ebpf/ bpf/    # eBPF programs (kernel side) user/   # User-space collector / exporter

At this stage:
- no full eBPF programs are required,
- placeholders are acceptable,
- focus is on conceptual clarity.

---

## Important Constraints

This reference implementation must NOT:
- block syscalls,
- enforce policies,
- act as a security control.

Its role is **memory**, not control.

---

## Goal

To demonstrate that system actions can be recorded as:

> functionally successful
> but causally questionable

This is the foundation for deeper OS, hypervisor,
and eventually hardware-level causal memory.
