# External Validation Note — Argentum `action_ref` Conformance

Validator: `giskard09` / `argentum-core`

Date: 2026-06-18

CML repository: https://github.com/safal207/Causal-Memory-Layer

External conformance vector: https://github.com/giskard09/argentum-core/blob/main/examples/conformance/cml/vectors.json

CrewAI discussion: https://github.com/crewAIInc/crewAI/issues/6063

Confirmation comment: https://github.com/crewAIInc/crewAI/issues/6063#issuecomment-4743250506

## What was validated

An independent repository published a CML-specific `action_ref` conformance set under:

```text
examples/conformance/cml/vectors.json
```

The external vector identifies:

```text
conformance_set_id = cml-action-ref-v1
implementer        = safal207/Causal-Memory-Layer
spec               = draft-giskard-aeoess-action-ref-v1
```

The shared preimage is:

```json
{
  "action_type": "tool_call",
  "agent_id": "researcher-agent",
  "scope": "search:task-42",
  "timestamp": "2026-06-18T10:40:00.123Z"
}
```

The compact sorted UTF-8 JSON payload is:

```text
{"action_type":"tool_call","agent_id":"researcher-agent","scope":"search:task-42","timestamp":"2026-06-18T10:40:00.123Z"}
```

Both implementations derive:

```text
c6fb63e34b2d61446745d86dd90ececf4c321f15e5023f8ffb897e5b0a32a16b
```

## Result

```text
Byte-identical derivation: PASS
External vector published: PASS
Independent repository reference: PASS
```

This demonstrates interoperable deterministic identity derivation for the pinned `action_ref` v1 vector.

## Relationship to CML

CML keeps three guarantees separate:

1. structural causality: uniqueness, parent resolution, and acyclicity;
2. deterministic identity: stable `action_ref` derivation;
3. optional integrity evidence: signatures or independently observed anchors.

The external vector validates item 2 for the pinned baseline. CML's own tests separately cover structural graph validation and sidecar invariance.

## Non-claims

This evidence does not establish:

- official CrewAI adoption or endorsement;
- production deployment inside CrewAI;
- full RFC 8785 coverage for arbitrary JSON values;
- cryptographic authorship or tamper resistance;
- policy enforcement, runtime blocking, compliance, or safety certification.

It is a narrow, reproducible external interoperability result for one published conformance vector.
