# CrewAI EventRecord structural audit (experimental)

This integration validates CrewAI's existing `RuntimeState.event_record` without
introducing a parallel trace schema or changing execution behavior.

- Adapter: [`cml/integrations/crewai_event_record.py`](../../cml/integrations/crewai_event_record.py)
- Contract tests: [`tests/test_crewai_event_record.py`](../../tests/test_crewai_event_record.py)
- Fixtures: [`tests/fixtures/crewai_event_record_v1.json`](../../tests/fixtures/crewai_event_record_v1.json)
- Public design discussion: [CrewAI issue #6063](https://github.com/crewAIInc/crewAI/issues/6063)

## Why this adapter exists

CrewAI events already carry typed relationship fields:

- `event_id`
- `parent_event_id`
- `previous_event_id`
- `triggered_by_event_id`
- `started_event_id`
- `emission_sequence`

CrewAI's `EventRecord` materializes edges only when a referenced event is already
present. A serialized event can therefore retain a missing relationship ID while
the corresponding graph edge is absent. This adapter audits the source event
fields directly so that unresolved lineage remains visible.

## Supported inputs

`validate_crewai_event_record(...)` accepts:

1. a CrewAI `EventRecord`-like object with a `nodes` mapping;
2. the serialized `{"nodes": ...}` representation;
3. an iterable of event-like objects or dictionaries.

CrewAI is not imported and is not a package dependency.

## Deterministic checks

The v1 adapter reports:

- duplicate `event_id` values;
- unresolved typed references;
- parent references that make an event appear to be a root;
- cycles across relationship fields;
- invalid start/completion event pairing;
- missing, duplicate, or backward `emission_sequence` relationships.

Findings use a canonical order:

```text
(code, event_id, field, referenced_event_id, message)
```

## Fixtures

The fixture set covers:

- a valid nested crew/task/tool trace;
- a missing parent;
- a missing start event;
- a mismatched lifecycle pair;
- a reference cycle;
- an emission-order violation;
- replayed events supplied out of storage order while preserving their IDs and
  emission sequence.

## Guarantee boundaries

This is a read-only structural audit. It does not:

- enforce policy or block runtime execution;
- prove that a decision was correct;
- prove authorship or authorization;
- sign or anchor events;
- provide immutable storage;
- provide compliance or safety certification.

Portable identity (`action_ref`), signatures, authority evidence, recalled-memory
influence, and review lineage remain separate optional layers.
