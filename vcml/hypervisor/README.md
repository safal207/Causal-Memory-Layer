# vCML Hypervisor Semantics (v0.6)

This document defines the **language and rules** for causal memory across
hypervisor boundaries — extending CML above a single OS instance.

---

## Motivation

A causal chain starting in a guest VM may cross into:
- the hypervisor itself (VMM / KVM / Xen)
- a sibling VM (same physical host)
- the host OS
- a management plane

Without cross-VM causal semantics, a NET_OUT from `VM-B` has no observable
causal link to a SECRET access inside `VM-A`, even when both share a tenant.

---

## Causal Domains at the Hypervisor Layer

Each isolation boundary becomes a distinct **causal domain** (DOM):

| Entity              | DOM value (canonical) |
|---------------------|----------------------|
| Host OS / VMM       | `KERNEL` (1)         |
| Management plane    | `PLATFORM` (2)       |
| Tenant service mesh | `SERVICE` (3)        |
| Individual VM       | `TENANT_A/B/C` (7–9) |
| Break-glass access  | `BREAK_GLASS` (14)   |

A **DOM change** always bumps `GEN` in the CTAG (see `vcml/CTAG.md`).

---

## Cross-VM Causal Record

When a causal chain crosses a VM boundary, the boundary-crossing record MUST:

1. Carry the `parent_cause` from **inside** the origin domain.
2. Set `permitted_by` to the hypervisor capability or API call that authorized
   the cross-domain action (e.g. `vmm:virtio_shared_mem`, `xen:grant_table`).
3. Bump DOM in the CTAG.
4. Include an `object` that identifies both source and target domain:

```json
{
  "action": "dom_crossing",
  "object": {
    "from_dom": "TENANT_A",
    "to_dom":   "TENANT_B",
    "mechanism": "shared_memory",
    "channel_id": "xen-grant-0x1a2b"
  }
}
```

---

## Invariant

> A causal chain originating in VM-A and terminating in VM-B MUST contain
> at least one `dom_crossing` record that identifies the authorized
> cross-domain mechanism.

If such a record is absent, the chain is **causally incomplete** at the
hypervisor boundary.

---

## Causal Gaps at the Hypervisor Layer

The hypervisor may not observe all events inside a guest. When a causal
chain enters from a guest and the hypervisor has no record of the prior
in-guest events:

- `parent_cause = null`
- `permitted_by = "unobserved_guest_context"`

This signals a **trusted causal gap** — the guest is responsible for its
own internal causal log.

---

## Multi-tenant Audit (semantic)

For a multi-tenant platform, the audit rule R3 extends:

**R3-HV**: If a `SECRET` access occurs in `TENANT_A` and a `NET_OUT`
occurs from `TENANT_B` within the same session or time window,
the `NET_OUT` record MUST contain a causal path (via `dom_crossing`)
back to the `SECRET` access in `TENANT_A`.

---

## Non-goals

- This document does not define how hypervisor events are captured.
- It does not define a new wire format.
- It does not replace VM introspection or VMM policy engines.

---

## Implementation Status

This is a **language and rules document** (v0.6).
Reference implementation is deferred to v0.8+.
