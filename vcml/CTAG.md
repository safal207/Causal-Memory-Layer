# CTAG (Causal Tags)

## Definition

**CTAG** is a compact 16-bit causal tag used as a fast, low-overhead semantic marker. It is designed to travel with vCML records, caches/metadata, and even hypervisor/hardware concepts. CTAG is **not** cryptography, a signature, or a policy system—it is a lightweight semantic hint for fast-path routing and attribution.

## 16-bit Layout (canonical)

```
 b15   b12 b11    b8 b7     b4 b3  b1 b0
+---------+---------+---------+------+--+
|  DOM    |  CLASS  |   GEN   |LHINT|SE|
+---------+---------+---------+------+--+
  4 bits     4 bits    4 bits  3 bits 1
```

* **b15..b12 = DOM (4 bits)**
* **b11..b8  = CLASS (4 bits)**
* **b7..b4   = GEN (4 bits)**
* **b3..b1   = LHINT (3 bits)**
* **b0       = SEAL (1 bit)**

## DOM table (0..15)

| Value | DOM          |
|------:|--------------|
| 0     | UNKNOWN      |
| 1     | KERNEL       |
| 2     | PLATFORM     |
| 3     | SERVICE      |
| 4     | USER         |
| 5     | ADMIN        |
| 6     | CI_CD        |
| 7     | TENANT_A     |
| 8     | TENANT_B     |
| 9     | TENANT_C     |
| 10    | SANDBOX      |
| 11    | UNTRUSTED    |
| 12    | THIRD_PARTY  |
| 13    | AGENT        |
| 14    | BREAK_GLASS  |
| 15    | RESERVED     |

## CLASS table (0..15)

| Value | CLASS        |
|------:|--------------|
| 0     | NONE         |
| 1     | READ         |
| 2     | WRITE        |
| 3     | EXEC         |
| 4     | NET_OUT      |
| 5     | NET_IN       |
| 6     | IPC          |
| 7     | PRIV         |
| 8     | CONFIG       |
| 9     | SECRET       |
| 10    | CRYPTO       |
| 11    | FIN_TX       |
| 12    | DATA_EGRESS  |
| 13    | ML_ACTION    |
| 14    | OVERRIDE     |
| 15    | SYSTEM       |

## GEN rules (epoch)

GEN is a 4-bit epoch counter (**mod 16**).

**Bump GEN on:**
- EXEC boundary
- PRIV boundary
- DOM change
- entering or exiting break-glass

## LHINT formula (3-bit)

LHINT is a cheap deterministic hint derived from the parent cause identifier.

**Canonical hash for v0.4:**
- `H(parent)` = **FNV-1a 64-bit** of the canonical UUID string (lowercase, with hyphens).

Formula:

```
LHINT = (H(parent_cause_id) XOR (DOM << 4) XOR (CLASS << 0) XOR (GEN << 2)) & 0b111
```

Notes:
- `H(parent_cause_id)` is a 64-bit unsigned integer.
- `& 0b111` keeps the lowest 3 bits.

## SEAL semantics

`SEAL = 1` when:
- `CLASS = OVERRIDE` / break-glass is active, **or**
- the causal chain must **not** auto-continue.

`SEAL = 0` for normal propagation.
