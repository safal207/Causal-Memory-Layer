# Causal Transition Guard

The Causal Transition Guard is a fail-closed runtime boundary between an LLM and side-effecting tools. It protects actions using a four-dimensional graph:

1. **Cause** — an active intent must propose the exact action;
2. **Space** — policy, authority, user, retrieved, tool, memory, secret, runtime, and external spaces remain distinct;
3. **Transition** — every side effect is an explicit state transition with exact operation, resource, and destination scope;
4. **Time** — policy and authorization must be active and not revoked at dispatch time.

## Security invariant

```text
natural-language claim != authorization
model reasoning != authorization
tool success != verified business success
```

A model may propose an action or assert that it is permitted. It cannot create the trusted graph path required to execute the action:

```text
trusted policy --DEFINES--> current authorization --AUTHORIZES--> exact action
```

## Fail-closed checks

The guard denies a transition when any of these conditions holds:

- no active intent path;
- no trusted policy-to-authorization-to-action path;
- authorization is expired or revoked;
- operation, resource, or destination is outside exact scope;
- secret-tainted data crosses an external boundary without explicit secret-egress scope;
- an external destination is missing.

## Trust boundaries

The implementation enforces authority-bearing node and edge construction:

- trusted policy nodes must originate from a configured policy source;
- trusted authorization nodes must originate from a configured authority service;
- only trusted policy nodes may create `DEFINES` edges;
- only trusted authorization nodes may create `AUTHORIZES` edges;
- claims from user, retrieved, tool, or memory space cannot be upgraded into authority by writing in a reasoning-like style.

The default source names are `policy-engine` and `authority-service`; production integrations should bind them to authenticated service identities and signed envelopes.

## Guarded tool gateway

`GuardedToolGateway` connects the graph decision to actual dispatch. The supported execution path is:

```text
LLM proposal
    -> immutable ActionEnvelope
    -> exact graph binding
    -> CausalTransitionGraph.evaluate()
    -> registered tool adapter
    -> postcondition verifier
    -> ExecutionReceipt
```

The gateway adds the runtime controls that a graph decision alone cannot provide:

- an action envelope binds `action_id`, operation, resource, destination, payload digest, nonce, and issue time;
- an allowed action must contain the exact `payload_hash` that will be dispatched;
- payload digests are deterministic and preserve scalar, sequence, byte, and mapping types;
- the gateway snapshots supported payloads before hashing and dispatch, so caller-side mutation cannot change adapter input after validation;
- destination or payload substitution is rejected before the adapter is called;
- unsupported or cyclic payloads fail closed and still produce an evidence receipt;
- a nonce can be claimed only once, blocking same-process replay;
- denied actions never reach registered file, network, or other tool adapters;
- successful execution can be checked by a postcondition verifier;
- unsupported adapter results are recorded as executed but unverified rather than losing the audit trail;
- receipts contain evidence and result digests but do not retain the raw payload.

Example:

```python
from cml.causal_transition_guard import (
    GuardedToolGateway,
    ToolRegistry,
    payload_digest,
)

payload = {"body": "quarterly report"}
# The ACTION node must include: attributes={..., "payload_hash": payload_digest(payload)}

registry = ToolRegistry()
registry.register(
    "http_post",
    post_adapter,
    verifier=lambda envelope, result: (
        result["status"] == 201
        and result["destination"] == envelope.destination
    ),
)

gateway = GuardedToolGateway(graph, registry)
receipt = gateway.execute_action(
    "send-report",
    payload,
    nonce="request-123",
)
```

Run the end-to-end CoT-forgery demo:

```bash
python scripts/run_asb15_gateway_demo.py
```

Expected result:

```text
read-secret: status=denied executed=False ...
send-secret: status=denied executed=False ...
adapter_calls=0
ASB-15 gateway: PASS
```

## Evidence

Every graph decision emits structured transition evidence containing:

- verdict and deterministic reason codes;
- observed time;
- active cause path;
- trusted authority path;
- secret-taint paths;
- participating spaces;
- proposed and actual state transitions.

Every gateway attempt additionally emits an `ExecutionReceipt` containing:

- the immutable envelope digest;
- graph evidence;
- dispatch status;
- whether an adapter was called;
- whether the external postcondition was verified;
- a result digest or stable error code.

This evidence can be recorded in CAEP/CML and independently verified after dispatch. A guard decision authorizes a transition; it does not replace postcondition verification of the external business state.

## Production boundary

The included replay and receipt stores are process-local reference implementations. Production deployments should replace them with durable, atomic storage and should also:

- authenticate policy and authority services;
- sign authorization and action envelopes;
- isolate adapter credentials so tools cannot be invoked outside the gateway;
- use durable idempotency or nonce storage across replicas;
- define rollback or compensation behavior for failed postconditions;
- persist receipts in an append-only or independently verifiable evidence store.
