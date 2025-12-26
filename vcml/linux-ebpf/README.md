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

See [exec.md](exec.md) for details on the boundary semantics.

---

## Implementation

The reference implementation is provided in `exec_monitor.py`.

It uses the BCC (BPF Compiler Collection) framework to:
1.  Attach to the `sched:sched_process_exec` tracepoint.
2.  Capture execution events (PID, PPID, filename).
3.  Maintain a user-space mapping of `PID -> CausalID`.
4.  Emit JSONL records with `parent_cause`.

### Usage

Requirements:
- Linux Kernel (with CONFIG_BPF_SYSCALL)
- Root privileges (sudo)
- `python3-bpfcc` or similar BCC package
- Kernel headers matching the running kernel

```bash
sudo ./exec_monitor.py
```

### Output

The tool outputs JSONL records.

- If a process is started by a parent *observed* by the monitor, `parent_cause` will be linked.
- If the parent was not observed (or existed before the monitor started), `parent_cause` will be `null`.

This satisfies the vCML invariant:
> A system may be functionally correct while being causally invalid (or incomplete).

---

## Important Constraints

This reference implementation must NOT:
- block syscalls,
- enforce policies,
- act as a security control.

Its role is **memory**, not control.

Non-goal: this is not a runtime security enforcement mechanism;
it is causal journaling.
