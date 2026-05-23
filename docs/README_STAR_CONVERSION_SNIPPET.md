# README Star Conversion Snippet

Use this block near the top of `README.md`, directly after the badges.

```md
![CML before-after causal audit visual](docs/assets/cml-before-after.svg)

## Why CML?

**Logs show what happened. CML checks why it was allowed.**

A workflow can pass every functional test and still be causally invalid: the action succeeded, but the approval, intent, or responsibility lineage is missing or broken.

```text
ordinary log:  action completed -> OK
CML audit:     parent_cause=approval-42 -> MISSING_PARENT
```

CML is an open-source causal audit layer for structured action traces, AI-agent workflows, high-stakes automation, and reviewable safety infrastructure.

> A system may be functionally correct while being causally invalid.

**Star this repo if you care about auditable AI agents, deterministic oversight, causal traces, and open-source AI safety infrastructure.**
```

## 30-second demo block

```md
## 30-second demo

Run the local API:

```bash
docker compose up --build
```

Then follow the Docker walkthrough:

```text
docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md
```

Expected failure class:

```text
CML-AUDIT-R1-MISSING_PARENT
```

The action may look operationally valid, but CML asks whether its causal parent exists.
```

## Developer use-cases block

```md
## Use CML when you need to audit

- AI-agent tool calls and action chains.
- Human approval handoffs.
- Automation workflows with sensitive actions.
- Fintech or compliance-review decision paths.
- Structured traces where responsibility lineage matters.
- Research benchmarks for causal validity in agentic systems.
```

## Comparison block

```md
## How CML differs

| System type | Usually answers | CML adds |
| :--- | :--- | :--- |
| Logs | What happened? | Was the action causally permitted? |
| Tracing | Where did execution go? | Did responsibility lineage survive the workflow? |
| Observability | What failed operationally? | What succeeded but had broken causal lineage? |
| Policy checks | Is this allowed now? | Why was this specific action allowed in this trace? |
| CML | Why was this action allowed? | Narrow audit primitive, not a full runtime safety stack. |
```
