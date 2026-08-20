# Identifier Population Witness v0.1

Identifier collision, scale and headroom measurements are facts about one exact
population. They are not timeless authority to apply a fold later.

This contract binds an identifier measurement to the population and writer
policy state that produced it, preserves historical collision evidence after
keys disappear, and fails closed if state changes between measurement and use.

It is additive. It does **not** add a new Memory Applicability verdict.

## Why this layer exists

A result such as:

```text
prefix_13 -> ZERO_AT_SCALE
headroom_chars = 1
```

may be completely correct when measured and still be unsafe to reuse later.
One key can be inserted, deleted, moved to another tenant/scope, or interpreted
under a different identifier policy before the consequential fold is applied.

The relevant distinction is therefore:

```text
correct measurement
    != current measurement
    != use-time-bound measurement
```

The same rule already appears elsewhere in CML:

- historical truth is not current authority (`MEMORY_APPLICABILITY_V0_1.md`);
- an index cannot prove missed deletions without source-side enumeration
  (`MEMORY_SOURCE_RECONCILIATION_V0_1.md`);
- check-then-act is weaker than use-time binding
  (`WITNESS_ISSUED_READ_TOKEN_CONTRACT.md`).

Identifier measurements need the same discipline.

## Population binding

A complete identifier population is committed as a deterministic SHA-256 over:

```text
scope
+
sorted SHA-256(key) identities
```

The witness records:

```text
scope
population_commitment
population_count
writer_contract_commitment
measured_at
identifier_policy_digest
identifier_policy_epoch
fold measurements
writer_contract_coverage
historical_key_coverage
historical collision ids
```

The use-time invariant is:

```text
measurement is valid for use
ONLY IF
measured_population_commitment == current_population_commitment
```

A count match is deliberately insufficient. `{A,B,C}` and `{A,B,D}` have the
same cardinality and different population commitments.

An incomplete current population cannot establish equality and therefore cannot
produce a use-time PASS.

## CHECK -> INSERT -> USE

The primary negative control is a measurement that is correct at check time and
stale at action time:

```text
P0: fold is measured as safe
        |
        | issue witness(P0)
        v
insert one key
        |
        v
P1: population changed
        |
        v
attempt to reuse witness(P0)
        -> fail closed / recompute
```

This is a TOCTOU problem, not a defect in the collision estimator.

A production migration may strengthen the reference shape further with a store
generation/CAS or transaction so population equality is consumed atomically at
the fold boundary. v0.1 defines the deterministic witness and validation rule;
it does not prescribe a storage engine.

## Historical collision evidence

A current scan sees only current keys. If two identifiers once collided under a
fold and one is later deleted, a surviving-key scan can become clean while the
historical loss event remains real.

Therefore this contract keeps two claims separate:

```text
current fold measurement
!=
historical fold integrity
```

`HistoricalKeyLedger` represents append-only identities for keys ever observed
in the scope. `HistoricalCollisionRecord` is sticky evidence of an observed
collision and is carried into later witnesses even when one side is gone.

Deletion is not allowed to rewrite:

```text
historical_collision_seen = true
```

back to false.

This mirrors source-side reconciliation: disappearance from the current set is
not proof that the missing object never existed.

## Writer policy binding

`identifier_contract()`-style declarations often describe the code running now.
Old records may have been written under a different normalization, case,
truncation or lookup policy.

Each `IdentifierKeyRecord` can therefore carry:

```text
writer_policy_digest
writer_policy_epoch
```

The witness separately reports `writer_contract_coverage` and records writer
policy mismatches. Unknown writer policy fails closed as `writer_policy_unbound`;
a known mismatch fails as `writer_policy_drift`.

This prevents a current declaration from retroactively describing a historical
store it did not write.

## Scope binding

Population commitments are scope-bound. A witness for one tenant/namespace does
not authorize reuse in another scope even if the visible keys and counts happen
to match.

Foreign scope produces a deterministic failure before population equality is
used as authority.

## Headroom composition

`FoldMeasurement` deliberately preserves both statistical and structural facts:

- `verdict`
- `keys_lost`
- `threshold_population`
- `collides_at_length`
- `headroom_chars`

A witness also exposes `at_cliff_edge` when:

```text
verdict == ZERO_AT_SCALE
and
headroom_chars == 1
```

This does not replace direct collision measurement. The precedence remains:

```text
model
< direct measurement
< state-bound measurement
< use-time-bound measurement
```

## Frozen v0.1 fixture

`tests/fixtures/identifier_population_witness_v0.1.json` freezes five failure
classes, each with a paired negative control:

1. **same count / different population** — cardinality equality cannot validate
   identity;
2. **CHECK -> INSERT -> USE** — a new key invalidates the measured population;
3. **collision -> delete -> clean current scan** — stale measurement fails while
   historical collision evidence remains visible;
4. **writer policy drift** — a current identifier policy cannot silently claim
   old records written under another policy;
5. **foreign scope** — a tenant/namespace witness cannot cross its boundary.

The benchmark contract requires all five cases and all five controls; there are
no silently excluded cases in v0.1.

## Non-claims

This witness does not claim that a fold with a fresh measurement is globally
safe forever. It does not predict future key distributions. It does not prove
historical completeness when the historical ledger is incomplete. It does not
make a statistical threshold authoritative over direct measured collisions.

It answers one narrower question precisely:

> Does this identifier measurement still describe the exact state and policy it
> is being asked to govern now?
