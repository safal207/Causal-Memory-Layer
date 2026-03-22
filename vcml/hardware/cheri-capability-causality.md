# CHERI Capability Causality

This document is a companion to `CTAG-8-16.md`.
It describes the mapping between CHERI capabilities and CML causal semantics.

---

## CHERI Primer (CML-relevant fields)

A CHERI capability is a fat pointer:

| Field        | Width  | Meaning                                  |
|--------------|--------|------------------------------------------|
| `address`    | 64 bit | Virtual address                          |
| `bounds`     | ~26 bit| Base + length of authorized memory range |
| `permissions`| 16 bit | Read, Write, Execute, Store-cap, etc.    |
| `otype`      | 18 bit | Object type / sealing type               |
| `tag bit`    | 1 bit  | Integrity tag (hardware-maintained)      |

---

## CML Mapping

| CHERI field  | CML semantic                                             |
|--------------|----------------------------------------------------------|
| `permissions`| `permitted_by` — what operations are causally authorized |
| `tag bit`    | SEAL bit in CTAG — chain may not auto-continue           |
| `otype`      | DOM + CLASS encoding (18 bits ≥ 8 bits CTAG-8)           |
| `bounds`     | `object` field (memory range being acted upon)           |
| `address`    | pointer to causal record or data under causal observation|

---

## Causal Lineage via `otype`

CHERI sealing assigns an `otype` to capabilities, preventing unseal without
the matching sealing capability. CML uses `otype` to carry causal lineage:

```
otype[17:10] = CTAG-8 (DOM + CLASS + GEN parity + SEAL)
otype[9:0]   = causal generation hash (low 10 bits of LHINT-extended)
```

A capability derived from a `SECRET`-tagged object (`CLASS=SECRET`) carries
that classification in its `otype`. When passed to a `send()` syscall, the
kernel (or a CHERI-aware library OS) can inspect the `otype` and emit a
causal record linking the send to the secret access.

---

## Enforcement vs. Observation

| Mode                   | Behaviour                                         |
|------------------------|---------------------------------------------------|
| Observation-only (CML) | Record that SECRET-tagged cap reached NET_OUT     |
| Soft enforcement       | Require caller to present unlock capability        |
| Hard enforcement       | Kernel rejects send if SECRET cap not unlocked    |

CML defaults to **observation-only**. Enforcement is a platform decision.

---

## Cross-compartment Causal Chains

In a CHERI-compartmentalised process:
- Each compartment has its own capability root.
- An IPC call between compartments carries a capability argument.
- CML records an `ipc` boundary crossing with:
  - `parent_cause` = last record in the calling compartment
  - `permitted_by` = the capability `otype` that authorized the IPC
  - `object` = the target compartment identifier

This produces a verifiable, hardware-rooted causal chain across compartments,
without any trusted third party.

---

## Implementation Status

Research and architecture document (v0.7).
A CHERI-CML prototype is planned for Morello / CheriBSD in v0.8.
