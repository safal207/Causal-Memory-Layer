# Lineage Verification Coverage v0.1

This contract freezes a measurable definition for `lineage_verification_coverage`.

The metric answers one narrow question:

> Of the records we know are derived, for what fraction can the system actually determine the current lineage state of every declared dependency well enough to make the lineage applicability decision?

It measures **verification capability**, not whether the lineage is valid.

A record whose active parent digest changed is lineage-verifiable even though it must later `REVALIDATE`. A record whose parent is observed as erased is also lineage-verifiable even when the erased parent no longer has a current digest.

## Formula

When the derived-record population is enumerable and non-empty:

```text
lineage_verification_coverage
    = lineage-verifiable derived records
      / all eligible derived records
```

The unit is the **derived record**, not the dependency edge.

A record is covered only when every dependency required for its lineage decision is verifiable.

## Denominator

The denominator contains every record in the measured population that is known to be derived.

A derived record with no populated `derived_from` / lineage edges **stays in the denominator** and is uncovered.

This is deliberate. Missing lineage metadata must not make the metric look better by causing the hard cases to disappear from measurement.

Direct/source records are outside this denominator.

This metric assumes the caller can enumerate the derived-record population. It does not silently substitute schema presence or observed edge count for population enumeration.

If the derived population cannot be enumerated, report:

```text
lineage_verification_coverage = null
undefined_reason = derived_population_unenumerable
```

If the population is enumerable but contains zero derived records, report:

```text
lineage_verification_coverage = null
undefined_reason = no_eligible_derived_records
```

Do not report either state as `0.0`.

## Numerator

A derived record enters the numerator only when:

1. it declares at least one lineage dependency;
2. dependency identities are unambiguous;
3. every dependency has a recognized current state;
4. every `active` dependency has both a verifiable expected digest and a verifiable observed digest.

Digest equality is **not** required for coverage.

```text
expected_digest != observed_digest
    -> lineage verification succeeded
    -> applicability later returns REVALIDATE
```

Coverage asks whether the system could determine the condition, not whether the condition was good.

## State before digest

Dependency state is evaluated before digest continuity.

For recognized non-active states:

```text
superseded
retired
erased
```

the state itself is already a decisive lineage observation. The dependency is therefore verifiable even if its current digest is absent.

This distinction is especially important for erasure:

```text
erased + observed_digest = null
    != lineage_unverifiable

instead:
    state says the parent was deliberately removed
    -> lineage invalidated
    -> re-derive from that parent is not permitted
```

By contrast:

```text
active + observed_digest = null
    -> lineage is not currently verifiable
    -> uncovered for this metric
```

The remedies differ, so the order is semantic rather than cosmetic.

## Record-level uncovered reasons

The reference implementation emits deterministic reasons including:

- `lineage_undeclared`
- `lineage_duplicate:<dependency_id>`
- `lineage_state_unobserved:<dependency_id>`
- `lineage_state_unknown:<dependency_id>:<state>`
- `lineage_expected_digest_unverifiable:<dependency_id>`
- `lineage_observed_digest_unverifiable:<dependency_id>`

These reasons are diagnostic evidence for the coverage number. They do not add new applicability verdicts.

## Frozen fixture

`tests/fixtures/memory_lineage_coverage_v0.1.json` freezes the metric around seven eligible derived records plus one direct/source control.

The expected result is:

```text
eligible derived records = 7
verified derived records = 4
uncovered derived records = 3
coverage = 4 / 7
```

The fixture deliberately proves four non-obvious properties:

1. a derived record with missing lineage edges remains in the denominator;
2. an active digest mismatch counts as verified;
3. an erased dependency with `observed_digest = null` counts as verified because state is decisive;
4. a duplicate dependency declaration is uncovered rather than silently accepted.

## Relationship to Current-State Applicability

The two contracts answer different questions:

```text
lineage_verification_coverage
    -> can the lineage be checked?

memory lineage applicability
    -> given the observation, may this historical memory still be used?
```

A system can therefore have high coverage and many `REVALIDATE` results. That is not a contradiction; it means the system is successfully detecting invalidated lineage.

The intended composition remains:

```text
retrieval reliability
    -> source integrity
    -> lineage verification coverage
    -> lineage / supersession applicability
    -> current-state applicability
    -> authority guard
    -> action
    -> evidence
```

## Interoperability rule

Implementations comparing this metric should report at least:

- eligible derived record count;
- verified derived record count;
- uncovered derived record count;
- coverage value or `null`;
- record-level uncovered reasons.

A single percentage without denominator and gap accounting is not sufficient for conformance.
