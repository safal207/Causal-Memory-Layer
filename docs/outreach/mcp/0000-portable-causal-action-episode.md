# SEP-0000: Portable Causal Action Episode for MCP Workflows

- **Title:** Portable Causal Action Episode for MCP Workflows
- **Authors:** safal207
- **Status:** proposal
- **Type:** Extensions Track (provisional; pending maintainer guidance)
- **Created:** 2026-07-30
- **Discussion:** https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2493
- **Reference implementation:** https://github.com/safal207/Causal-Memory-Layer/tree/main/docs/experimental/caep

## Abstract

This SEP proposes an optional portable execution-record profile for Model Context Protocol workflows called a Causal Action Episode (CAEP). A CAEP record represents one externally meaningful state transition while keeping user intent, authorization, decision, exact MCP dispatch, observed outcome, declared postconditions, independent verification, recovery, and causal lineage distinct.

The profile addresses a gap between per-call telemetry and workflow-level auditability. An MCP tool can return a successful result even when the intended business outcome is false because of stale observations, concurrent actors, retries, partial failures, or cross-server state changes. A portable record allows independently operated components to communicate what was intended, what was authorized, what was executed, what state was observed, who verified the outcome, and how a divergence was contained or repaired.

This proposal standardizes a JSON record and its acceptance semantics. It does not require MCP implementations to retain audit history, standardize a storage system, expose private reasoning, or adopt a particular policy language. Wire bindings are optional and may be defined separately after the record profile is validated across implementations.

## Motivation

MCP provides interoperable communication between clients and servers, but a successful protocol response does not necessarily establish that a user-level objective was fulfilled.

Examples include:

- a payment tool returns success after another actor has already created a payment;
- a delete tool begins after authorization has been revoked;
- a timed-out idempotent call is retried before its real outcome is observed;
- an agent follows an instruction embedded in retrieved content rather than the user's request;
- a coding agent produces a patch with green tests while violating a business invariant;
- one agent delegates an action to another agent without transferring authority;
- a compensating action restores one condition while creating a larger secondary failure.

Per-call logs and interceptors are valuable, but they usually answer only parts of the audit question. They may establish that a method was called at a particular time and returned a particular payload. They do not necessarily preserve:

1. the user intent against which the action should be evaluated;
2. the authorization and policy decision in force at dispatch time;
3. the critical postconditions that define business success;
4. an independently observed outcome;
5. the causal relationship between a divergence and its recovery;
6. portable integrity bindings across separately operated MCP servers.

The decentralized case is particularly difficult. When a workflow spans independent servers, no single server may possess the complete execution history or trust boundary. A portable profile allows each participant or orchestrator to emit a verifiable episode that can be composed into a workflow-level record without requiring one central gateway.

## Goals

This proposal aims to provide:

- a portable record for one externally meaningful action episode;
- explicit separation of intent, authorization, decision, execution, outcome, and verification;
- business postconditions that are not inferred from transport success;
- causal-parent bindings for multi-step and recovery workflows;
- deterministic canonicalization and tamper-evident digests;
- a lifecycle that distinguishes completion, containment, verification, and recovery;
- enough semantics for competing implementations and conformance tests.

## Non-goals

This proposal does not standardize:

- storage, indexing, retention, or query infrastructure;
- a universal workflow engine or orchestration model;
- a policy language such as Rego, CEL, SQL, or JSONPath;
- evaluation of postcondition expressions;
- private chain-of-thought or hidden model reasoning;
- publisher authentication or a public-key infrastructure;
- mandatory signatures;
- mandatory server-side audit retention;
- a user interface;
- production certification or regulatory compliance.

## Specification

### Record media type and profile

A CAEP record is a JSON object identified by:

```json
{
  "profile": "org.causal-memory-layer.caep",
  "schema_version": "0.1.0"
}
```

The identifier is provisional until MCP governance assigns or approves an extension identifier.

An implementation that claims conformance to this profile MUST satisfy the structural and semantic requirements below.

### Top-level fields

A record MUST contain:

- `profile`
- `schema_version`
- `episode_id`
- `workflow_id`
- `status`
- `time`
- `intent`
- `authorization`
- `decision`
- `action`
- `outcome`
- `expected_postconditions`
- `verification`
- `recovery`
- `causal_parent_ids`
- `integrity`

A record MAY contain:

- `state_before`
- `state_after`
- `privacy`
- `extensions`
- `supersedes`

Unknown extension fields SHOULD be placed under `extensions` rather than added at the top level.

### Episode and workflow identity

`episode_id` MUST uniquely identify the episode within the producer's declared identity scope.

`workflow_id` identifies the larger workflow or user request to which the episode belongs. Multiple records MAY share a workflow ID.

`causal_parent_ids` contains the episode IDs that directly caused, authorized, informed, or required the current transition. It is not merely a temporal predecessor list.

### Time model

`time` MUST distinguish:

- `valid_time`: when the represented transition was true in the external system;
- `recorded_time`: when the episode was recorded;
- `source_clock`: the clock or system that produced the timestamps.

Timestamps MUST include an offset or use UTC.

When present, the following orderings MUST hold:

```text
valid_time <= recorded_time
action.dispatch.started_at <= action.dispatch.completed_at
action.dispatch.completed_at <= outcome.observed_at
outcome.observed_at <= verification.verified_at
action.dispatch.started_at <= authorization.expires_at
```

A profile MAY define stricter cross-record temporal rules.

### Intent

`intent` records the user-level or system-level objective against which the transition is evaluated.

It MUST contain:

- `code`: a stable machine-oriented intent identifier;
- `summary`: a human-readable description;
- `initiator`: the actor that originated the request;
- `request_ref`: a reference to the originating request or artifact;
- `constraints`: explicit constraints that remain in force during execution and recovery.

Intent MUST describe the desired outcome rather than merely repeat a tool name.

### Authorization

`authorization` records whether the action was permitted and under what scope.

It MUST contain:

- `decision`: `authorized`, `denied`, or `expired`;
- `actor`: the policy or approval actor;
- `scope.action`;
- `scope.resource`;
- `scope.constraints`;
- `policy_refs`;
- `approval_refs`;
- `expires_at` when authorization is time-bounded.

A write or destructive action MUST NOT be accepted as verified or recovered if authorization was denied or expired at dispatch start.

### Decision

`decision` records the bounded operational choice made after evaluating intent, state, and authorization.

It MUST contain:

- `code`;
- `maker`;
- `summary`;
- `reason_codes`;
- `record_ref`.

`reason_codes` and evidence references MUST be sufficient for audit without exposing private chain-of-thought.

### Action dispatch

`action` MUST distinguish side-effect class and exact dispatch metadata.

`action.dispatch` MUST contain:

- `server_ref`;
- `tool_name`;
- `protocol_version`;
- `executor`;
- `correlation_id`;
- `request_ref`;
- `request_digest`;
- `tool_schema_digest`;
- `started_at`;
- `completed_at` when completed.

For retryable writes, `idempotency_key` SHOULD be included.

`action.side_effect` SHOULD classify the operation as `none`, `local_write`, `external_write`, or `destructive`.

`action.blast_radius` SHOULD describe the maximum expected scope of change.

### Outcome

`outcome` represents what the action executor reported or what the producer observed immediately after execution.

It MUST contain:

- `status`;
- `result_type`;
- `observed_at`;
- `response_ref`;
- `response_digest`.

A successful outcome MUST NOT by itself imply that the episode status is `verified`.

### Expected postconditions

`expected_postconditions` declares the conditions that define acceptance of the transition.

Each postcondition MUST contain:

- `id`;
- `expression`;
- `language`;
- `severity`;
- `evidence_refs`.

`severity` MUST be one of `informational`, `important`, or `critical`.

This profile records expressions and evidence but does not standardize expression evaluation. The producer or verifier is responsible for evaluation.

A write or destructive transition accepted as `verified` or `recovered` MUST declare at least one critical postcondition.

### Verification

`verification` records a post-execution verdict derived from observed state and declared postconditions.

It MUST contain:

- `verdict`: `verified`, `diverged`, `inconclusive`, or `not_performed`;
- `independence`: `independent`, `same_process`, or `unknown`;
- `verifier`;
- `checks`;
- `verified_at` when verification was performed.

Each check MUST identify one declared postcondition and record `pass`, `fail`, or `unknown`.

For status `verified` or `recovered`:

- the verdict MUST be `verified`;
- independence MUST be `independent`;
- the verifier MUST be identified;
- the verifier MUST differ from the action executor and decision maker where actor identity is available;
- every declared postcondition MUST have a corresponding check;
- every critical postcondition MUST pass;
- no verification check MAY target an undeclared postcondition.

### Recovery

`recovery` describes containment and compensation capabilities or actions.

It MUST contain:

- `status`: `not_required`, `available`, `contained`, `in_progress`, `recovered`, or `failed`;
- `reversibility`;
- `action_refs`.

When a rollback or compensation tool exists, `rollback_tool` SHOULD be included.

A record with status `recovered` MUST:

- declare `recovery.status` as `recovered`;
- have verification verdict `verified`;
- identify at least one causal parent representing the divergence or contained episode;
- bind each causal parent to its verified digest;
- represent the smallest justified reversible transition toward the declared intent constraints.

Recovery MUST NOT erase or rewrite the original divergence record.

### Lifecycle status

`status` MUST be one of:

- `blocked`: dispatch was prevented;
- `completed`: execution completed, but business acceptance is not established;
- `contained`: a divergence was detected and further harm was bounded;
- `verified`: the intended transition passed independent verification;
- `recovered`: a divergence was repaired and the final state passed independent verification;
- `failed`: the episode failed without verified recovery.

`completed` is intentionally weaker than `verified`.

A producer MUST NOT label an episode `verified` solely because an MCP tool call completed successfully.

### State references

`state_before` and `state_after` MAY contain references to observed state artifacts.

Each reference SHOULD contain:

- `ref`;
- `media_type`;
- `digest`;
- `classification`.

This profile does not require dereferencing or storing artifact content.

### Canonicalization and integrity

The initial canonicalization identifier is `caep-json-v1`.

`caep-json-v1` serializes UTF-8 JSON with:

- object keys sorted lexicographically;
- no insignificant whitespace;
- non-ASCII text preserved;
- non-finite numbers rejected.

The record digest MUST cover all fields except:

- `integrity.record_digest`;
- `integrity.signature`.

`integrity.record_digest` MUST identify the digest algorithm and value. SHA-256 MUST be supported by conforming implementations.

For each ID in `causal_parent_ids`, `integrity.parent_digests` MUST contain the declared digest of that parent record.

A verifier validating a non-root record MUST obtain every declared parent, recompute the parent's own record digest, and verify the child's parent binding. Missing, undeclared, or mismatched parents MUST fail validation.

Digests provide integrity and causal binding, not publisher authenticity.

### Optional signatures

`integrity.signature` MAY contain a signature over the canonical record digest and selected identity metadata.

This SEP does not define a trust anchor, key-discovery mechanism, certificate profile, or signature policy. A future SEP MAY standardize authenticity separately.

### Privacy

`privacy` SHOULD declare:

- data classification;
- whether personal data is present;
- redacted paths.

Implementations SHOULD minimize request, response, and state content in the envelope and use artifact references plus digests when full content is unnecessary.

CAEP MUST NOT require hidden model reasoning or private chain-of-thought.

### Transport bindings

This SEP standardizes the portable record profile, not a mandatory wire method.

An implementation MAY:

- attach an inline record to protocol metadata when size and policy permit;
- attach a URI reference and digest to protocol metadata;
- expose the record as an MCP resource;
- persist or exchange the record out of band.

A future revision or companion SEP MAY standardize one or more wire bindings after interoperability experience demonstrates which mechanism is appropriate.

Regardless of binding, the decoded record MUST have identical semantics and canonical integrity rules.

## Rationale

### Why an episode rather than a complete workflow ledger?

One action episode is small enough for independent producers to emit and verify. Workflow records can be composed by following workflow IDs and causal-parent references. Requiring every server to understand or store a complete workflow would recreate a centralized gateway assumption and would not fit decentralized trust boundaries.

### Why separate outcome and verification?

The action executor has direct knowledge of tool completion but may not have independent visibility into the resulting business state. Keeping outcome and verification separate prevents transport success from being treated as user-intent success.

### Why explicit intent and authorization?

An execution trace answers what happened. An audit trail also needs to answer why the action was permitted and which outcome it was intended to achieve. Intent and authorization therefore remain first-class and independently referenceable.

### Why causal parents rather than only ordered events?

Temporal order does not establish derivation or responsibility. A record may be written later while representing an earlier valid-time transition. Explicit causal parents capture which prior records informed or required the current episode.

### Why independent verification?

A system that checks its own side effect through the same state path may reproduce the same stale view or fault. Independent verification is required for the strongest accepted statuses while weaker statuses remain available when independence cannot be established.

### Why keep wire bindings out of the initial scope?

The existing implementation demonstrates that the same record can be produced through real MCP sessions and viewed or verified independently. Standardizing the data profile first allows experimentation with inline metadata, resource references, and external stores without prematurely choosing a transport mechanism.

## Alternatives considered

### Application-specific logs

Application logs are useful but do not provide portable field semantics, lifecycle states, canonical integrity, or causal-parent verification across implementations.

### OpenTelemetry traces

Trace context and spans provide excellent observability and correlation. They generally do not standardize user intent, authorization, business postconditions, independent acceptance, or compensation semantics. CAEP can reference trace IDs and coexist with OpenTelemetry.

### Interceptors only

Interceptors can observe individual calls and enforce local policy. They do not by themselves create a portable post-execution episode spanning independent servers and trust boundaries.

### Provenance graph only

Provenance graphs answer what informed what. They do not necessarily record authorization, exact action dispatch, business acceptance, containment, or bounded recovery. CAEP records can contribute nodes and edges to a broader provenance graph.

### A centralized gateway ledger

A gateway can solve the problem for deployments where all actions pass through one trusted gateway. It does not solve decentralized workflows where independent MCP servers do not share one operator or trust boundary.

## Backward compatibility

The profile is optional and additive. Existing clients and servers can ignore records or references they do not understand.

No existing MCP method or message is changed by the record-only profile.

A future wire-binding SEP MUST define negotiation and compatibility behavior before making protocol-level changes.

## Reference implementation

The reference implementation is available at:

https://github.com/safal207/Causal-Memory-Layer/tree/main/docs/experimental/caep

It includes:

- JSON Schema Draft 2020-12;
- semantic, temporal, duplicate-key, digest, and causal-parent validation;
- successful, divergent, contained, and recovered records;
- a cross-process interoperability demo;
- real MCP Python SDK client sessions over stdio;
- separate action and independent verifier server processes;
- a stale-state duplicate-payment scenario;
- digest-bound compensation and recovery;
- a public Trust Console with provenance-manifest verification;
- deterministic tests across Python 3.10, 3.11, and 3.12.

Direct evidence:

https://safal207.github.io/Causal-Memory-Layer/trust-console/?evidence=mcp&record=mcp_sdk_duplicate_recovered

## Candidate conformance scenarios

A conformance suite for this profile SHOULD include:

1. verified write with one passing critical postcondition;
2. tool success followed by a failed critical postcondition and `contained` status;
3. recovered episode bound to the digest of the contained parent;
4. missing causal parent rejection;
5. parent digest mismatch rejection;
6. record tampering rejection;
7. verifier equal to executor rejection for accepted status;
8. expired authorization rejection;
9. undeclared verification target rejection;
10. `completed` record proving that transport completion does not imply verification.

The existing Agent Safety Benchmark supplies related behavioral scenarios but is not itself an MCP conformance suite.

## Security implications

### False assurance

Consumers may mistake a valid digest for trusted authorship. Implementations MUST describe integrity and authenticity separately.

### Sensitive data retention

Execution records can contain request, response, identity, authorization, and state metadata. Producers SHOULD use references, minimization, redaction, and deployment-specific retention controls.

### Malicious producers

A producer can create an internally consistent but false record. Independent evidence, signatures, trust anchors, and verifier policy are deployment concerns not solved by record canonicalization alone.

### Replay and duplicate actions

Records SHOULD preserve correlation IDs and idempotency keys for retryable writes. A record does not itself prevent replay; execution systems must enforce idempotency and authorization.

### Compromised verifier

Verifier independence reduces correlated failure but does not guarantee correctness. Deployments should define verifier trust and evidence sources appropriate to their risk model.

### Recovery abuse

A broad compensating action can cause more harm than the original divergence. Recovery records therefore preserve intent constraints, blast radius, authorization, and independent postconditions.

### Denial of service

Unbounded parent graphs, artifact references, or record sizes could consume excessive resources. Implementations SHOULD enforce depth, size, and count limits and SHOULD detect cycles before recursive validation.

## Open questions

1. Should the first proposal be Extensions Track, Standards Track interoperability, or Informational?
2. Should MCP define a preferred metadata or resource binding in the first version?
3. Which extension identifier and media type should be registered?
4. Should signatures be a separate SEP or an optional profile in the same family?
5. Should causal relationships distinguish authorization, derivation, and recovery edge types?
6. Should critical postcondition evaluation languages remain fully implementation-defined?
7. Which existing MCP conformance infrastructure is appropriate for a record-only profile?
8. Should the profile align directly with OpenTelemetry span links or W3C trace context?

## References

- MCP Discussion #2493: https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2493
- MCP SEP Guidelines: https://modelcontextprotocol.io/community/sep-guidelines
- CAEP reference implementation: https://github.com/safal207/Causal-Memory-Layer/tree/main/docs/experimental/caep
- MCP-generated evidence: https://safal207.github.io/Causal-Memory-Layer/trust-console/?evidence=mcp&record=mcp_sdk_duplicate_recovered
- CML Agent Safety Benchmark: https://github.com/safal207/Causal-Memory-Layer/tree/main/benchmarks/agent_safety

## Copyright

This document is placed in the public domain or under the CC0-1.0-Universal license, whichever is more permissive.

Disclosure: prepared with AI assistance under human direction and review.
