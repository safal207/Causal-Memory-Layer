# CTAG Hardware Mapping (v0.7)

This document defines how the 16-bit CTAG maps to hardware metadata fields,
pointer metadata, and capability systems — demonstrating that causal tags are
a natural fit for silicon, not a software afterthought.

---

## Motivation

If CTAG can be carried in hardware, causal memory becomes **zero-copy** and
**near-zero-overhead**. The semantic cost of causality is paid once at design
time, not at every software boundary.

---

## 8-bit Compact CTAG (CTAG-8)

For constrained environments (cache line tags, DRAM metadata, embedded MCUs):

```
b7..b5  = DOM   (3 bits, reduced table)
b4..b2  = CLASS (3 bits, reduced table)
b1      = GEN   (1 bit, parity of full GEN)
b0      = SEAL  (1 bit)
```

LHINT is dropped in CTAG-8. Full 16-bit CTAG is carried in memory-side metadata
or reconstructed from context.

### Reduced DOM table (CTAG-8)

| Value | DOM         |
|------:|-------------|
| 0     | UNKNOWN     |
| 1     | KERNEL      |
| 2     | SERVICE     |
| 3     | USER        |
| 4     | TENANT      |
| 5     | SANDBOX     |
| 6     | AGENT       |
| 7     | BREAK_GLASS |

### Reduced CLASS table (CTAG-8)

| Value | CLASS      |
|------:|------------|
| 0     | NONE       |
| 1     | READ       |
| 2     | WRITE      |
| 3     | EXEC       |
| 4     | NET_OUT    |
| 5     | SECRET     |
| 6     | PRIV       |
| 7     | OVERRIDE   |

---

## RISC-V Pointer Masking

RISC-V (Pointer Masking extension, Smmpm/Ssnpm) reserves top bits of
virtual addresses for software metadata. CTAG-8 fits naturally:

```
VA[63:56] = CTAG-8  (8 bits reserved via pointer masking)
VA[55:0]  = canonical virtual address
```

This allows the CPU to carry causal tags on every pointer, at hardware speed,
without changing ABI for existing code. The OS or hypervisor sets the mask;
the causal tag propagates through load/store operations transparently.

**Use case**: A pointer to a SECRET buffer carries `CLASS=SECRET` in its tag.
Any NET_OUT that dereferences a tagged pointer can be causally linked by
hardware, without software instrumentation.

---

## CHERI Capability Causality

CHERI capabilities carry permissions, bounds, and a tag bit. CML maps naturally:

| CHERI field    | CML mapping                              |
|----------------|------------------------------------------|
| `permissions`  | `permitted_by` (semantic capability ref) |
| `tag bit`      | `SEAL` bit in CTAG                       |
| `otype`        | `DOM` + `CLASS` (semantic type of object)|
| `bounds`       | `object` field (address range)           |

A CHERI capability that has been derived from a SECRET object carries the
causal lineage in its `otype`. When it crosses a network boundary, the
hardware enforces that only authorized capabilities may reach the NIC —
the causal chain is **hardware-enforced**, not just observed.

**CML + CHERI invariant**:

> A CHERI capability derived from a SECRET object MUST NOT reach a NET_OUT
> boundary unless its `otype` encodes an authorized causal chain.

---

## ARM MTE (Memory Tagging Extension)

ARM MTE provides 4-bit allocation tags on 16-byte granules. CTAG-4 mapping:

```
bits [3:2] = DOM  (2 bits: KERNEL=0, SERVICE=1, USER=2, UNTRUSTED=3)
bits [1:0] = CLASS (2 bits: NONE=0, SECRET=1, NET_OUT=2, PRIV=3)
```

This enables use-after-free and buffer-overflow detection to carry causal
context, e.g., a SECRET-tagged memory region that is accessed after being freed
is detectable AND causally attributed.

---

## Implementation Notes

- Hardware CTAG mapping is **additive** — existing software continues to work.
- CTAG in hardware is a **hint**, not an enforcement mechanism (consistent with
  CML semantics).
- Hardware enforcement (CHERI) is opt-in and controlled by the platform.

---

## Implementation Status

This is a **research and architecture document** (v0.7).
No hardware implementation is provided; this defines the mapping language.
