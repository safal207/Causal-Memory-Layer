# CrewAI `action_ref` listener (experimental)

This example connects CrewAI tool-completion events to deterministic action identities that can be validated as a CML causal graph.

- Helper: [`cml/integrations/action_ref.py`](../../cml/integrations/action_ref.py)
- Listener: [`examples/crewai_action_ref_listener.py`](../../examples/crewai_action_ref_listener.py)
- Contract tests: [`tests/test_action_ref.py`](../../tests/test_action_ref.py)

## Public design discussion

- [CrewAI Issue #6063](https://github.com/crewAIInc/crewAI/issues/6063)
- [CML guarantee-separation proposal](https://github.com/crewAIInc/crewAI/issues/6063#issuecomment-4741945546)
- [Listener sketch](https://github.com/crewAIInc/crewAI/issues/6063#issuecomment-4742109035)
- [CML implementation follow-up](https://github.com/crewAIInc/crewAI/issues/6063#issuecomment-4742233073)
- [Byte-level alignment feedback](https://github.com/crewAIInc/crewAI/issues/6063#issuecomment-4742345957)
- [Digest confirmation and external conformance publication](https://github.com/crewAIInc/crewAI/issues/6063#issuecomment-4743250506)

These links preserve public design provenance. They do not imply an official CrewAI integration, endorsement, or roadmap commitment.

## External conformance evidence

An independent repository now publishes a CML-specific conformance vector:

- [`argentum-core/examples/conformance/cml/vectors.json`](https://github.com/giskard09/argentum-core/blob/main/examples/conformance/cml/vectors.json)
- [CML external validation note](../evidence/external_validation/2026-06-18-argentum-action-ref-conformance.md)

The external vector identifies `safal207/Causal-Memory-Layer` as the implementer and confirms byte-identical derivation of the pinned baseline digest.

## Guarantee separation

1. **Structural causality (CML):** parent references resolve and the graph is acyclic.
2. **Identity stability (`action_ref`):** the same canonical metadata produces the same SHA-256 handle.
3. **Tamper evidence (optional):** signatures or independently observed anchors remain separate sidecars.

## Event mapping

```text
action_ref = SHA-256(canonical JSON({
  action_type,
  agent_id,
  scope,
  timestamp
}))
```

`timestamp` is RFC 3339 UTC with exactly millisecond precision, for example:

```text
2026-06-18T10:40:00.123Z
```

The emitted record contains `action_ref`, `action_ref_scheme`, `parent_action_ref`, `session_id`, `task_id`, `timestamp`, and metadata.

## Baseline vector

The restricted v1 preimage contains four strings with ASCII field names. Compact sorted UTF-8 JSON therefore produces the same byte sequence as JCS/RFC 8785 for this data shape.

The pinned test vector uses:

```text
agent_id      = researcher-agent
action_type   = tool_call
scope         = search:task-42
timestamp     = 2026-06-18T10:40:00.123Z
expected hash = c6fb63e34b2d61446745d86dd90ececf4c321f15e5023f8ffb897e5b0a32a16b
```

## Listener usage

```python
from examples.crewai_action_ref_listener import ActionRefListener

records = []
listener = ActionRefListener(sink=records.append)
```

A real application can provide `parent_resolver` and `session_resolver` callbacks.

## Deterministic checks

1. identical canonical metadata produces the pinned baseline reference;
2. changed metadata produces a different reference;
3. an unresolved parent is reported as broken lineage;
4. integrity sidecars do not alter the structural result.

## Non-claims

This experimental bridge does not provide policy enforcement, runtime blocking, key management, signing, immutable storage, compliance certification, or safety certification.
