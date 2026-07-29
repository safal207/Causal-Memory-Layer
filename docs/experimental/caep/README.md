# Portable Causal Action Episode (CAEP) — experimental v0.1.0

CAEP is an experimental execution-record profile for Causal Memory Layer (CML) and MCP workflows.

It represents:

`observable state → intent → authorization → decision → exact tool dispatch → outcome → independent verification → recovery`

CAEP is meant to complement ordinary logs and provenance traces. It asks whether a tool action was an authorized, observable, and verifiable state transition.

## What is included

- `caep.schema.json` — JSON Schema Draft 2020-12.
- `caep.example.json` — valid external-write example.
- `validate_caep.py` — schema validation plus cross-field semantic checks.

## Validate locally

```bash
python -m pip install jsonschema
python docs/experimental/caep/validate_caep.py \
  docs/experimental/caep/caep.example.json
```

Expected result:

```text
VALID
```

## Core invariants

1. Intent, authorization, decision, dispatch, outcome, and verification are separate records.
2. Expected postconditions are checked against independently observed state.
3. An actor marked as an independent verifier cannot also be the action executor.
4. Prior history is not rewritten; newer records use `supersedes`.
5. `valid_time` and `recorded_time` are recorded separately.
6. Write and destructive actions require explicit authorization and recovery metadata.
7. Decision records contain reason codes and evidence references, not private chain-of-thought.

## Relationship to CML

CML checks causal lineage such as missing parents, ambiguous roots, and broken responsibility paths. CAEP proposes a portable envelope that can carry those relationships across multi-server MCP workflows while also recording postconditions and recovery.

This prototype is intentionally non-normative. `org.causal-memory-layer.caep` and the `$id` URN are working identifiers, not official MCP registrations or security certification.
