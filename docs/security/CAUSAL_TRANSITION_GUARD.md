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

## Evidence

Every decision emits structured transition evidence containing:

- verdict and deterministic reason codes;
- observed time;
- active cause path;
- trusted authority path;
- secret-taint paths;
- participating spaces;
- proposed and actual state transitions.

This evidence can be recorded in CAEP/CML and independently verified after dispatch. A guard decision authorizes a transition; it does not replace postcondition verification of the external business state.
