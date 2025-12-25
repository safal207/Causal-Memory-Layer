# Causal Memory Layer (CML)

CML is a foundational memory layer for recording reasons, permissions, and responsibility behind actions, not just events or results. It enables systems in AI, fintech, security, and distributed computing to preserve meaning and causal accountability across time, independent of execution or transport.

## Scope

The primary goal of Causal Memory Layer is to define **why** a state change happened, linking it to the authorization and intent that preceded it.

### What is Causal Memory?
*   **Immutable History of Intent**: Records the decision-making process and authorization chains.
*   **Causal Links**: Explicitly connects effects to their causes (e.g., "Action B happened because Action A authorized it").
*   **Accountability**: Attaches identity and responsibility to state transitions.

### Out of Scope
*   **Transport**: CML is not responsible for moving bytes between nodes. It relies on underlying transport protocols but does not define them.
*   **Execution**: CML does not execute code or business logic. It records the causality of the execution.
*   **Storage Implementation**: CML defines the *semantics* of storage (what is stored and how it relates), not the *mechanics* (SQL, NoSQL, Block storage).

### Differentiation

| System Type | Focus | CML Difference |
| :--- | :--- | :--- |
| **Transport (HTTP, TCP)** | Moving data | CML cares about the *meaning* of the data, not the delivery. |
| **Tracing (OpenTelemetry)** | Performance & Debugging | Tracing follows *what* happened. CML records *why* it was allowed to happen. |
| **Execution (Lambda, K8s)** | Running tasks | CML is the memory of the execution, not the computer. |

## Foundations

CML is designed to be:
*   **Language Agnostic**: Usable in any programming environment.
*   **Transport Agnostic**: Independent of how messages are delivered.
*   **Infrastructure Agnostic**: Deployable on any stack.

This repository serves as the anchor point for specifications, formal definitions, and invariants of the Causal Memory Layer.
