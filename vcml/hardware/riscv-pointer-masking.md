# CTAG on RISC-V Pointer Masking

This document is a companion to `CTAG-8-16.md`.
It details the specific RISC-V extensions relevant to hardware CTAG embedding.

---

## Relevant Extensions

| Extension | Description                                       |
|-----------|---------------------------------------------------|
| Smmpm     | Machine-mode pointer masking                      |
| Ssnpm     | Supervisor-mode pointer masking                   |
| Smnpm     | Non-privileged (U-mode) pointer masking           |
| J-ext     | Pointer masking for JIT/managed runtimes (draft)  |

All pointer masking extensions allow software to ignore the top N bits of
virtual addresses (N configurable, typically 7 or 16). These bits are
available for software-defined metadata — CTAG maps directly here.

---

## Encoding

With 7-bit pointer masking enabled (pmm=1):

```
VA[63]       = unused (must be zero for canonical addr)
VA[62:56]    = CTAG-7 (7 bits, subset of CTAG-8 dropping SEAL)
VA[55:0]     = canonical virtual address (56-bit addressable)
```

With 16-bit pointer masking (pmm=3, where supported):

```
VA[63:48]    = CTAG-16 (full 16-bit CTAG)
VA[47:0]     = canonical virtual address
```

---

## OS / Hypervisor Integration

The kernel sets `pmm` (pointer masking mode) per process via CSR writes.
For CML-aware processes:

1. Kernel assigns a DOM value to the process at creation.
2. DOM + initial CLASS are encoded in the top bits of all pointers returned
   by `mmap` / `brk`.
3. When a process executes a syscall that crosses a causal boundary (exec,
   open, connect), the kernel may update the tag bits before handing
   the pointer back.
4. The causal tag travels with the pointer through registers and memory,
   without any software overhead on the hot path.

---

## Threat Model Interaction

Pointer masking does not enforce access control — it is advisory.
A malicious or buggy process can strip or forge tags in user space.

For CML purposes, this is acceptable: CTAG is a **semantic hint**, not a
security enforcement mechanism. Observation and auditability are the goals.

Enforcement, where desired, requires CHERI or a privilege-level check
(see `cheri-capability-causality.md`).
