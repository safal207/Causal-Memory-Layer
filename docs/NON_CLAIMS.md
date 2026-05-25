# CML Non-Claims

Status: reviewer-facing scope boundary.

This document explains what CML does not claim.

## Purpose

CML is intentionally narrow.

It contributes one focused primitive:

```text
causal-validity checking for structured action traces
```

The project is strongest when its claims remain specific, reproducible, and evidence-backed.

## What CML claims

CML claims that structured action traces can be inspected for causal permission and responsibility lineage.

It can help detect cases such as:

- missing parent cause;
- malformed root authority;
- ambiguous permission lineage;
- broken responsibility handoff;
- action success despite invalid causal grounding;
- structured trace records that cannot explain why an action was allowed.

## What CML does not claim

CML does not claim:

- full AI alignment;
- certified compliance;
- production security certification;
- universal model evaluation;
- prevention of all unsafe actions;
- replacement of logs, traces, SIEM, observability, or policy engines;
- replacement of human review;
- replacement of legal, compliance, or security teams;
- automatic truth discovery;
- causal inference from arbitrary unstructured text;
- guaranteed correctness for arbitrary real-world workflows;
- complete agent governance.

## Not a logging replacement

CML does not replace logs.

Logs remain useful for recording what happened.

CML adds a different question:

```text
Why was this action allowed?
```

A useful implementation may use logs as input, but CML is not itself a general-purpose logging system.

## Not a tracing replacement

CML does not replace distributed tracing or observability.

Tracing helps show where execution went and how services interacted.

CML asks whether responsibility, permission, and parent-cause lineage survived the workflow.

## Not a policy engine replacement

CML does not replace runtime policy checks.

A policy engine often answers:

```text
Is this action allowed now?
```

CML asks:

```text
Why was this specific action allowed in this trace?
```

## Not a compliance product

CML is not currently certified for regulatory, legal, or compliance use.

It may support audit reasoning, but it should not be represented as certified compliance infrastructure.

## Not production security certification

CML is not a production security certification system.

It can contribute to security-relevant reasoning by making broken causal lineage visible, but it is not a replacement for threat modeling, secure engineering, penetration testing, access control, or incident response.

## Not universal AI safety

CML does not solve AI safety in general.

It focuses on one narrow but important failure class:

```text
actions that appear valid or successful but lack a valid causal permission / responsibility chain
```

## Benchmark limitation

The current benchmark is deterministic and scaffolded.

It is useful as seed evidence, but it does not prove broad empirical generalization.

Current reviewer-safe benchmark statement:

```text
CML includes a deterministic safety-eval scaffold with tracked expected findings.
```

Do not inflate this into a claim of general real-world safety performance.

## Correct funding framing

The strongest funding framing is:

```text
CML is an open-source causal audit primitive for AI-agent and high-trust automation traces.
```

It should be funded to expand:

- benchmark coverage;
- external validation;
- integration examples;
- trace compatibility;
- causal invalidity taxonomy;
- reviewer-facing reproducibility.

## Bottom line

CML is not trying to be everything.

It is trying to make one missing layer inspectable:

```text
causal permission and responsibility lineage
```
