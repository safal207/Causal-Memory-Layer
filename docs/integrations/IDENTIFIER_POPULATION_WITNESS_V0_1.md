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

`current population` is not defined as "whatever objects still exist at the
source." It is the population that the **actual lookup path keys on** for the
measurement being governed.

That distinction matters for append-only or audit-style stores. Deleting a source
object may leave its key addressable in the store. A surviving-source scan can
therefore be clean while the lookup keyspace still contains a colliding key.
Time-binding cannot repair a witness that committed to the wrong set.

`IdentifierPopulationSnapshot.population_basis` names that relation. The default
is:

```text
lookup_keyspace
```

A different basis can be represented, but the verifier must state the basis it
expects. A witness issued over `surviving_sources` cannot validate a claim that
requires `lookup_keyspace`, even if both happen to contain the same visible keys.

A complete identifier population is committed as a deterministic SHA-256 over:

```text
scope
+
population_basis
+
commitment_fields = (scope, population_basis, key_digest)
+
sorted SHA-256(key) identities
```

The witness records:

```text
scope
population_basis
population_commitment
population_commitment_fields
measurement_predicate = identifier_collision_headroom
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

The use-time invariant is therefore:

```text
measurement is valid for use
ONLY IF
witness.population_basis == expected_population_basis
AND
current_snapshot.population_basis == expected_population_basis
AND
measured_population_commitment == current_population_commitment
```

A count match is deliberately insufficient. `{A,B,C}` and `{A,B,D}` have the
same cardinality and different population commitments. Likewise, equal key sets
under different population bases produce different commitments.

An incomplete current population cannot establish equality and therefore cannot
produce a use-time PASS.

### Commitment scope and evidentiary sufficiency

A valid hash is not automatically sufficient evidence for every question a
consumer may ask.

This witness explicitly declares:

```text
population_commitment_fields = (scope, population_basis, key_digest)
measurement_predicate = identifier_collision_headroom
```

Those fields are sufficient for the identifier collision/headroom predicate this
contract governs. They are **not** sufficient to prove, for example, that an
observation's content is still current; that predicate would also depend on the
observed content digest.

The verifier must therefore keep two questions separate:

```text
Does the commitment verify?
!=
Is this commitment sufficient for the predicate being established?
```

In compact form:

> Cryptographic validity is not evidentiary sufficiency. A commitment must cover
> exactly the fields the claimed predicate depends on.

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

A source-side current scan sees only current source objects. If two identifiers
once collided under a fold and one source is later deleted, a surviving-source
scan can become clean while the historical loss event remains real. In an
append-only store, the deleted source's key may additionally remain addressable,
which means the collision can remain in force rather than merely historical.

Therefore this contract keeps two claims separate:

```text
current fold measurement
!=
historical fold integrity
```

and requires the current fold measurement itself to be taken over the declared
lookup population basis.

`HistoricalKeyLedger` represents append-only identities for keys ever observed
in the scope. `HistoricalCollisionRecord` is sticky evidence of an observed
collision and is carried into later witnesses even when one side is gone.

Deletion is not allowed to rewrite:

```text
historical_collision_seen = true
```

back to false.

This mirrors source-side reconciliation: disappearance from the current source
set is not proof that the missing object never existed, and it is not proof that
the backing lookup store stopped addressing it.

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

A separate regression control freezes the population-basis boundary surfaced by
an append-only path-keyed implementation: identical visible keys committed as
`surviving_sources` and `lookup_keyspace` must not be interchangeable. The
negative path fails as `population_basis_mismatch`; the same witness validates
when the consumer explicitly asks for the basis it was issued over.

## Non-claims

This witness does not claim that a fold with a fresh measurement is globally
safe forever. It does not predict future key distributions. It does not prove
historical completeness when the historical ledger is incomplete. It does not
make a statistical threshold authoritative over direct measured collisions.

The library cannot infer a backend's true lookup relation from a list of keys;
the caller must supply an honest `population_basis`, and the relying consumer
must state the basis its predicate actually requires.

It answers one narrower question precisely:

> Does this identifier measurement still describe the exact lookup population,
> commitment scope and policy it is being asked to govern now?
