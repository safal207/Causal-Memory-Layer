# Witness-Issued Read Token Contract v0.1

## Purpose

Strengthen exact read coverage from post-hoc correlation to use-time binding.

The existing vCML `read_id` contract can correlate `sys_enter_read`,
`sys_exit_read`, and persisted CML observations. The stronger question is:

> Who was allowed to choose the correlation identity, and could the ledger invent
> it after the read already happened?

A witness-issued read token answers that by moving token creation outside the
ledger and consuming the token at the actual kernel read boundary.

## Contract

```text
Independent witness / token issuer
              |
              | issues one-shot read_id
              v
      kernel active-token state
              |
              | consumed at sys_enter_read
              v
        successful read boundary
          /               \
         /                 \
        v                   v
kernel completion       application ledger
(read_id, object_id)    CausalRecord(read_id, object_id)
         \                 /
          \               /
           v             v
             reconciliation
```

The ledger is not allowed to derive its `read_id` from the completion witness.
It must receive the witness-issued token before the consequential read and
persist that same identity in its own observation path.

## One-shot invariant

```text
issue(token, thread)
read_1(thread) consumes token at sys_enter_read
read_2(thread) without a new issue does not carry token
```

The token is copied into the per-read kernel start state before the active token
is deleted. `sys_exit_read` can therefore attest the same token after completion,
but a later read cannot reuse it.

This is use-time binding rather than check-then-act:

```text
wrong:
verify token -> time passes -> read -> hope token still means the same thing

reference shape:
issue token -> consume token at read entry -> carry consumed identity to exit
```

## Exact reconciliation invariant

For a successful token-bound read:

```text
external_completion.read_id == issued_read_id
ledger_record.read_id        == issued_read_id
external_completion.object_id == ledger_record.object.object_id
```

The existing CML verifiers remain authoritative:

- `check_causal_record_read_observation_coverage()` establishes exact `read_id`
  coverage;
- `check_causal_record_read_object_coverage()` establishes exact
  `(read_id, object_id)` coverage.

This contract adds provenance and one-shot consumption; it does not add a new
applicability status.

## Linux reference proof

`vcml/linux-ebpf/runtime_witness_issued_read_token_proof.py` is a live BCC proof.
It deliberately uses two processes / paths:

1. the witness controller generates a 128-bit token, injects it into a BPF map
   keyed to the stopped target thread, and independently captures read
   completions;
2. the application child receives the same token before execution and authors a
   standalone `CausalRecord` after the first successful read.

The child then performs a second read on the same fd without receiving another
token. The proof passes only if the second kernel event is unbound.

The BPF program also resolves the fd to `(device, inode)` at `sys_enter_read` so
exact object coverage is checked at the same use boundary.

## Required PASS conditions

A live proof must establish all of the following simultaneously:

```text
first read completed successfully
first read resolved a kernel object
first read carried the issued token
kernel token == issued token
active token was consumed at the read boundary
application ledger action == read
application ledger read_id == issued token
exact read-id coverage holds
exact read-object coverage holds
second read completed successfully
second read used the same fd
second read did not inherit/reuse the first token
```

## Failure modes

### Ledger invents another token

```text
kernel witness = A
ledger record   = B
```

Result: exact read-id coverage fails.

### Object substituted after correlation

```text
read_id matches
kernel object = X
ledger object = Y
```

Result: exact object coverage fails.

### Token remains reusable

```text
read_1 token = A
read_2 token = A without new issue
```

Result: one-shot invariant fails.

### Witness unavailable

No token-bound PASS may be manufactured. Runtime infrastructure should preserve
`UNSUPPORTED_ENVIRONMENT` evidence and fail the gate rather than treating lack
of BPF capability as success.

## Non-claims

The reference token is a correlation primitive, not by itself an authorization
credential, capability, signature, or globally unique identity guarantee.
Production deployments that use the token as authority need authenticated
issuance, subject/scope binding, expiry, and replay policy appropriate to their
threat model.

The BPF-map injection used by the live proof is a reference mechanism for
showing use-time consumption. It is not a prescription for every production
transport.

## Architectural consequence

The trust chain becomes:

```text
external issuer
  -> one-shot token
  -> kernel use boundary
  -> successful completion
  -> independent ledger observation
  -> exact read-id reconciliation
  -> exact object reconciliation
```

A ledger can still state what it observed. It cannot create the external token
that makes its own observation complete.
