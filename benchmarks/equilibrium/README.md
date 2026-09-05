# Causal Equilibrium conformance fixtures

This directory contains the versioned, machine-readable contract for the experimental **Causal Equilibrium Point**.

The plain-language idea is a final control pause:

> Before an agent finishes an action, did it leave behind enough resolved causal context to show that nothing material was silently forgotten?

The fixtures are conformance tests, not performance benchmarks. They define the expected state and findings for a fixed input snapshot so another implementation can reproduce the same result without calling CML internals.

## Current contract

- Contract: `cml-causal-equilibrium-conformance-v1`
- Schema version: `cml-equilibrium-fixtures-v1`
- Fixture file: [`v1/fixtures.json`](v1/fixtures.json)
- Runner: [`run.py`](run.py)

Each fixture contains:

| Field | Meaning |
|---|---|
| `fixture_id` | Stable identifier for the case. |
| `schema_version` | Version of the fixture contract. |
| `findings_order` | Canonical ordering rule for expected findings. |
| `description` | Human-readable purpose of the case. |
| `snapshot` | Input for `CausalEquilibriumSnapshot`. |
| `known_refs` | References resolvable by the evaluator. |
| `expected_state` | `BALANCED`, `UNSTABLE`, or `INDETERMINATE`. |
| `expected_findings` | Exact ordered finding objects. |

## Canonical finding order

Findings must be normalized and sorted using:

```text
(code, severity_rank, refs_lexicographic, message)
```

Severity ranks are:

```text
FAIL = 0
WARN = 1
```

The serialized contract value is:

```text
code_asc,severity_fail_before_warn,refs_lexicographic_asc,message_asc
```

References inside a finding are sorted lexicographically before comparison.

## Covered cases

The v1 set covers:

1. fully resolved balanced context;
2. missing required counterevidence;
3. unresolved recalled-memory influence;
4. unresolved supporting material;
5. unresolved counterevidence;
6. preserved consolidation provenance;
7. lost consolidation provenance;
8. explicitly unresolved references;
9. an empty checkpoint;
10. multiple simultaneous findings in canonical order.

The tests also reverse all set-like input lists and verify that the result does not change.

## Run the benchmark

From the repository root:

```bash
python benchmarks/equilibrium/run.py \
  --fixtures benchmarks/equilibrium/v1/fixtures.json \
  --json-out /tmp/equilibrium-report.json \
  --markdown-out /tmp/equilibrium-report.md
```

The runner:

- validates the fixture schema before evaluation;
- sorts fixtures by `fixture_id`;
- compares exact states and ordered findings;
- writes deterministic JSON and Markdown reports;
- records the tested Git commit;
- prints the JSON report SHA-256 for external reproduction.

Use `--implementation-commit VALUE` or the `CML_IMPLEMENTATION_COMMIT` environment variable to pin the commit identifier explicitly.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Every fixture matched exactly. |
| `1` | At least one semantic result differed. Reports are still written. |
| `2` | The fixture contract or CLI input was malformed. |

A report contains aggregate counts plus, for every fixture:

```text
fixture_id
expected_state
actual_state
expected_findings
actual_findings
passed
```

## Run tests

```bash
pytest -q \
  tests/test_equilibrium_fixtures.py \
  tests/test_equilibrium_benchmark_runner.py
```

## Rules for adding a fixture

- Keep the existing v1 semantics unchanged.
- Use a unique stable `fixture_id`.
- Include every snapshot field explicitly.
- Sort `known_refs` and expected finding refs lexicographically.
- Preserve the canonical finding order.
- Add a new schema version rather than silently changing the meaning of an existing fixture.

## Non-claims

A matching result proves only that an implementation reproduced the published experimental contract.

It does not prove that an action is:

- objectively correct;
- safe;
- fair;
- compliant;
- morally balanced;
- supported by true evidence.

`BALANCED` means the declared audit conditions were satisfied. It does not mean the underlying decision was right.
