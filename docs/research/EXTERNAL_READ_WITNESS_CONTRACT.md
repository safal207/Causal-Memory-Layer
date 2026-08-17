# External Read Witness Contract v0.2

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

The reference Linux eBPF monitor derives a local correlation identity from:

```text
(pid, tid, bpf_ktime_get_ns() captured at sys_enter_read)
```

The kernel-side read-start map carries that entry timestamp to `sys_exit_read`, so an exit record can retain the same `read_id` even if the userspace read-entry perf event is lost.

The identifier is a correlation token, not a claim of cryptographic authenticity or global uniqueness. Scope binding and independent witness provenance remain required.

Successful completion means `sys_exit_read` returned `ret >= 0`, including EOF at `ret == 0`. Failed reads (`ret < 0`) do not require a successful-content observation.

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

## Design rule

Do not add new applicability statuses for store failures.

Store-level failures belong before applicability.

Keep aggregate liveness and exact per-read coverage distinct:

- aggregate evidence answers whether the channel was alive at all;
- identity evidence answers whether specific successful reads are covered.

## Reference implementation direction

Potential witnesses:

- eBPF syscall monitor
- kernel audit stream
- independent runtime hook
- signed external receipt stream

The witness must fail independently from the store it validates.

The current vCML Linux eBPF reference monitor still associates paths using the last opened path for a PID. Therefore `read_id` strengthens syscall correlation, but it does **not** yet prove exact fd-to-path attribution. A future fd-aware kernel mapping is a separate contract.

## Verification tests

A valid aggregate implementation should pass:

1. Healthy collector produces reads and observations.
2. Application collector is disabled.
3. External witness observes a known read.
4. Memory store has no observation.
5. Admissibility fails.

A valid identity implementation should also pass:

1. `sys_enter_read` creates a boundary correlation token.
2. `sys_exit_read` carries the same token from kernel state.
3. Two externally completed reads `{A, B}` and ledger observations `{A, B}` pass.
4. `{A, B}` vs `{A}` fails with `B` reported missing.
5. `{A, B}` vs `{A, A}` still fails despite equal raw counts.
6. A duplicate external completion identifier fails closed.
7. An unavailable identity witness never produces PASS.

This proves the system can detect both total collector silence and selective loss instead of silently converting either into a valid applicability verdict.
