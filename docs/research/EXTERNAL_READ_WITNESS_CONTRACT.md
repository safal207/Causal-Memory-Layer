# External Read Witness Contract v0.1

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

## Core invariant

```text
reads > 0 => observations > 0
```

The left side must come from an observation source independent from the memory ledger.

A ledger cannot prove its own completeness.

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

### Key disagreement

```text
identifier_written != identifier_queried
```

Expected result:

```text
admissibility = false
```

The system must not convert lookup failure into missing evidence.

## Design rule

Do not add new applicability statuses for store failures.

Store-level failures belong before applicability.

## Reference implementation direction

Potential witnesses:

- eBPF syscall monitor
- kernel audit stream
- independent runtime hook
- signed external receipt stream

The witness must fail independently from the store it validates.

## Verification test

A valid implementation should pass:

1. Healthy collector produces reads and observations.
2. Application collector is disabled.
3. External witness observes a known read.
4. Memory store has no observation.
5. Admissibility fails.

This proves the system detects missing observation capability instead of silently producing a verdict.
