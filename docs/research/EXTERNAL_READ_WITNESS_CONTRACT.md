# External Read Witness Contract v0.3

## Purpose

Define the boundary between observed memory records and evidence that the observation channel itself was alive.

Applicability answers:

> Is this record admissible now?

External Read Witness answers the prior question:

> Was there an independent observation path capable of producing this record?

## Contract

```text
External reality
      |
      v
ExternalReadWitness
      |
      v
Admissibility Preconditions
      |
      v
Memory Observation
      |
      v
Applicability Evaluation
```

## Aggregate liveness invariant

```text
reads > 0 => observations > 0
```

The left side must come from an observation source independent from the memory ledger.

A ledger cannot prove its own completeness.

This aggregate invariant detects a dead observation channel, including the day-one-dead case when an independent witness sees reads but the ledger records none. It does **not** prove that every read was observed.

## Exact per-read coverage invariant

When the external boundary can carry a stable correlation identity, use the stronger invariant:

```text
for every read_id in externally_completed_reads(scope):
    read_id in ledger_observation_read_ids(scope)
```

Equivalently:

```text
ExternalCompletedReadIds(scope) ⊆ LedgerObservationReadIds(scope)
```

This is stronger than count equality. Two external reads `{A, B}` and two ledger rows `{A, A}` have equal counts but fail exact coverage because `B` is missing.

The v0.8 Linux eBPF monitor derives a local correlation identity from:

```text
(pid, tid, bpf_ktime_get_ns() captured at sys_enter_read)
```

The kernel-side read-start map carries that entry timestamp to `sys_exit_read`, so an exit record can retain the same `read_id` even if the userspace read-entry perf event is lost.

The identifier is a correlation token, not a claim of cryptographic authenticity or global uniqueness. Scope binding and independent witness provenance remain required.

Successful completion means `sys_exit_read` returned `ret >= 0`, including EOF at `ret == 0`. Failed reads (`ret < 0`) do not require a successful-content observation.

## Derived identity vs witness-issued identity

A kernel-derived `read_id` gives strong boundary correlation, but provenance still matters. If one collector emits both the external completion record and the ledger observation, that collector must not be treated as an independent proof of its own completeness.

The stronger reference shape is a witness-issued token:

```text
external issuer -> one-shot read_id -> kernel use boundary
                                  \-> application ledger
```

The token exists before the consequential read and is consumed at `sys_enter_read`. The ledger receives the token independently instead of learning it from `sys_exit_read` after the fact.

See `WITNESS_ISSUED_READ_TOKEN_CONTRACT.md` for the one-shot runtime contract and negative-control proof.

## Persistence boundary

`CausalRecord` preserves an optional top-level `read_id` through dictionary, JSONL, and loader round-trips. The record's ordinary `id` remains distinct: entry and completion records may have different causal-record identities while sharing one boundary `read_id`.

Exact ledger reconciliation uses persisted records with:

```text
action == "read" and read_id != null
```

A persisted `read_exit` record is deliberately **not** accepted as proof of ledger observation coverage. Otherwise the external completion witness could prove its own completeness simply by being stored beside the records it is supposed to check.

Legacy records without `read_id` remain valid CML records, but they cannot contribute to exact identity coverage.

## Kernel object identity

v0.8 resolves the numeric fd at `sys_enter_read` through the task fd table and binds the read to the backing kernel `(device, inode)` object. That identity is carried through the per-read kernel start state to `sys_exit_read`.

This closes the old fd-reuse ambiguity for exact object reconciliation. The path string remains descriptive evidence from the userspace last-open-by-PID cache; object coverage therefore uses kernel `object_id`, not path equality.

The live fd-reuse proof in `runtime_fd_reuse_proof.py` additionally verifies on a real kernel that the same numeric fd can be reused for two distinct inodes while the object witness remains correct.

## Failure modes

### Collector unavailable

```text
external_reads > 0
internal_observations == 0
```

Expected result:

```text
admissibility = false
```

### Partial collector loss

```text
external_completed_read_ids = {A, B}
ledger_observation_read_ids = {A}
```

Expected result:

```text
exact_coverage = false
missing_read_ids = {B}
```

### Key disagreement

```text
identifier_written != identifier_queried
```

Expected result:

```text
admissibility = false
```

The system must not convert lookup failure into missing evidence.

### Foreign scope

A witness produced for one session or scope must not establish liveness or exact coverage for another scope, even if its read identifiers happen to match.

### Self-attested completeness

```text
same failure domain produces external witness and ledger observation
```

Expected result:

```text
do not claim independent completeness
```

Correlation can still be useful, but independence must be supplied by architecture rather than inferred from field equality.

## Design rule

Do not add new applicability statuses for store failures.

Store-level failures belong before applicability.

Keep aggregate liveness and exact per-read coverage distinct:

- aggregate evidence answers whether the channel was alive at all;
- identity evidence answers whether specific successful reads are covered;
- object evidence answers whether both sides mean the same kernel object;
- witness-issued identity strengthens provenance by preventing post-hoc ledger token invention.

## Reference implementation direction

Potential witnesses:

- eBPF syscall monitor
- kernel audit stream
- independent runtime hook
- signed external receipt stream
- witness-issued one-shot read-token service

The witness must fail independently from the store it validates.

## Verification tests

A valid aggregate implementation should pass:

1. Healthy collector produces reads and observations.
2. Application collector is disabled.
3. External witness observes a known read.
4. Memory store has no observation.
5. Admissibility fails.

A valid identity implementation should also pass:

1. `sys_enter_read` creates or consumes a boundary correlation token.
2. `sys_exit_read` carries the same token from kernel state.
3. `CausalRecord` preserves the token through persistence round-trips.
4. Two externally completed reads `{A, B}` and persisted read observations `{A, B}` pass.
5. `{A, B}` vs `{A}` fails with `B` reported missing.
6. `{A, B}` vs `{A, A}` still fails despite equal raw counts.
7. A `read_exit` record alone cannot prove its own ledger coverage.
8. A duplicate external completion identifier fails closed.
9. An unavailable identity witness never produces PASS.
10. For witness-issued mode, a second read without a new token cannot reuse the first token.

This proves the system can detect total silence, selective loss, object substitution, and token replay instead of silently converting them into a valid applicability verdict.
