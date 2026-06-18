# CrewAI `action_ref` listener (experimental)

This example connects CrewAI tool-completion events to deterministic action identities that can be validated as a CML causal graph.

- Helper: [`cml/integrations/action_ref.py`](../../cml/integrations/action_ref.py)
- Listener: [`examples/crewai_action_ref_listener.py`](../../examples/crewai_action_ref_listener.py)
- Contract tests: [`tests/test_action_ref.py`](../../tests/test_action_ref.py)

## Public design discussion

This experimental bridge grew out of an open technical discussion in the CrewAI repository:

- [CrewAI Issue #6063 — Example proposal: optional causal audit for agent action traces](https://github.com/crewAIInc/crewAI/issues/6063)
- [CML guarantee-separation proposal](https://github.com/crewAIInc/crewAI/issues/6063#issuecomment-4741945546)
- [`ToolUsageFinishedEvent` listener sketch from the discussion](https://github.com/crewAIInc/crewAI/issues/6063#issuecomment-4742109035)
- [CML implementation follow-up with code and tests](https://github.com/crewAIInc/crewAI/issues/6063#issuecomment-4742233073)

These links preserve the public design provenance and technical context. They do not imply an official CrewAI integration, endorsement, roadmap commitment, or inclusion in CrewAI core.

## Guarantee separation

The integration keeps three guarantees separate:

1. **Structural causality (CML):** parent references resolve and the graph is acyclic.
2. **Identity stability (`action_ref`):** the same canonical metadata produces the same SHA-256 handle.
3. **Authorship or tamper evidence (optional):** signatures, transparency logs, or other independently observed anchors.

A reproducible hash is a portable identity. By itself, it does not prove that a backend did not rewrite both the event metadata and the hash after the fact.

## Event mapping

At the `ToolUsageFinishedEvent` boundary, the example derives:

```text
action_ref = SHA-256(canonical JSON({
  action_type,
  agent_id,
  scope,
  timestamp_ms
}))
```

The emitted record contains:

```text
action_id
action_ref
action_ref_scheme
parent_action_id
parent_action_ref
session_id
task_id
timestamp
metadata
```

`started_at` is converted to `timestamp_ms` so the identity is anchored to dispatch intent. `finished_at` is retained as metadata.

## Canonicalization scope

The dependency-free helper uses compact sorted UTF-8 JSON for the restricted v1 preimage: three strings and one integer. Before claiming full RFC 8785/JCS conformance in production, verify the implementation against the draft's external conformance vectors or use a dedicated JCS implementation.

## Listener usage

```python
from examples.crewai_action_ref_listener import ActionRefListener

records = []
listener = ActionRefListener(sink=records.append)
```

A real application can provide `parent_resolver` and `session_resolver` callbacks so the listener emits `parent_action_ref` and `session_id` from the surrounding crew context.

## Deterministic checks

The test suite fixes four properties:

1. identical canonical metadata produces an identical `action_ref`;
2. changed metadata produces a different `action_ref`;
3. an unresolved `parent_action_ref` is reported as broken lineage;
4. optional integrity sidecars do not alter the structural CML result.

## Non-claims

This experimental bridge does not provide policy enforcement, runtime blocking, key management, signing, immutable storage, compliance certification, or safety certification.
