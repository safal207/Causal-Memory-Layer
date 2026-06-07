# Grant Evidence Pack — CML 0.4.0

This document summarizes concrete evidence that Causal Memory Layer (CML) has moved beyond a concept into a reproducible open-source technical artifact.

It is intended for grant applications, fellowship applications, research updates, and reviewer-facing summaries.

## One-paragraph summary

Causal Memory Layer (CML) reached a concrete open-source release milestone: `causal-memory-layer==0.4.0` was published to production PyPI with a GitHub Release and reproducible install path. The release passed GitHub CI/tests, deterministic safety benchmark, package validation, TestPyPI publication, production PyPI publication, production PyPI install smoke testing, CLI smoke testing, and MCP core import smoke testing. The narrow claim is that CML 0.4.0 is a package-validated, installable causal-validity audit prototype for structured action traces.

## Installable artifact

```bash
pip install causal-memory-layer==0.4.0
```

Package:

```text
https://pypi.org/project/causal-memory-layer/0.4.0/
```

GitHub Release:

```text
https://github.com/safal207/Causal-Memory-Layer/releases/tag/v0.4.0
```

Repository:

```text
https://github.com/safal207/Causal-Memory-Layer
```

## Validation evidence

### Production PyPI install smoke test

```text
https://github.com/safal207/Causal-Memory-Layer/actions/runs/27101272184/job/79982287069
```

Confirmed checks:

- install package from production PyPI,
- run `cml --help`,
- verify `import cml`,
- verify MCP core import,
- verify `core.health()`,
- verify `cml-mcp` optional dependency guard.

### Production PyPI publication workflow

```text
https://github.com/safal207/Causal-Memory-Layer/actions/runs/27101018313
```

Confirmed jobs:

- build and validate distributions,
- publish distributions to PyPI,
- skip TestPyPI for production release trigger.

### Package validation workflow

```text
https://github.com/safal207/Causal-Memory-Layer/actions/runs/27063042787/job/79879380002
```

Confirmed checks:

- install validation tools,
- install package with dev extras,
- run tests,
- run deterministic safety benchmark,
- build source and wheel distributions,
- validate package metadata,
- install built wheel in a fresh environment.

### TestPyPI publication workflow

```text
https://github.com/safal207/Causal-Memory-Layer/actions/runs/27069357386
```

Confirmed checks:

- build and validation job passed,
- TestPyPI publication passed,
- install smoke test from TestPyPI passed.

## Benchmark evidence

Current deterministic benchmark snapshot:

```text
6/6 matched
```

Related docs:

```text
docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md
benchmarks/RESULTS.md
benchmarks/fixtures/
```

## Integration evidence

CML now includes a CrewAI-style agent trace audit example:

```text
examples/crewai_style_causal_audit.py
docs/integrations/CREWAI_STYLE_CAUSAL_AUDIT.md
```

Outreach issue:

```text
https://github.com/crewAIInc/crewAI/issues/6063
```

The integration example demonstrates how a multi-agent workflow trace can be mapped into CML records and audited for missing parent causes / broken responsibility lineage.

## Why this matters for AI safety / agent oversight

Many agent frameworks can show that a task, tool call, or workflow step completed successfully.

CML asks a narrower question:

```text
Was the action causally permitted by a valid upstream approval, task, or responsibility path?
```

This is useful for agent oversight because an action can be operationally successful while still being causally invalid.

Example:

```text
assistant_agent sends an external email
but the referenced human approval / parent task is missing
```

CML can flag this as broken causal lineage.

## Narrow claim

```text
CML 0.4.0 is a package-validated, installable causal-validity audit prototype for structured action traces.
```

## Non-claims

CML 0.4.0 does not claim:

- production AI safety,
- regulatory compliance,
- runtime enforcement,
- complete jailbreak detection,
- complete security coverage,
- certification readiness,
- stable Cause Band semantics,
- future prediction,
- quantum security guarantees.

## Short update block for applications

```text
Since submitting the application, Causal Memory Layer reached a concrete reproducible artifact milestone. I published `causal-memory-layer==0.4.0` to production PyPI with a GitHub Release and install path (`pip install causal-memory-layer==0.4.0`). The release passed CI/tests, deterministic safety benchmark, package validation, TestPyPI publication, production PyPI publication, production install smoke testing, CLI smoke testing, and MCP core import smoke testing. This strengthens the project’s tractability evidence: the work is no longer only a proposal, but an installable open-source causal-validity audit prototype for structured action traces.
```

## Reviewer-friendly phrasing

```text
Logs show what happened. CML checks why it was allowed.
```

```text
A system may be functionally correct while being causally invalid.
```
