# causal-memory-layer 0.4.0 — package-validation-ready CML prototype

This is the first production PyPI release candidate for `causal-memory-layer`.

CML is an open-source causal audit layer for structured action traces. It focuses on checking whether an action has a valid causal permission / responsibility lineage, not only whether the action happened.

> Logs show what happened. CML checks why it was allowed.

## Install

```bash
pip install causal-memory-layer==0.4.0
```

Then:

```bash
cml --help
```

For experimental MCP support:

```bash
pip install "causal-memory-layer[mcp]==0.4.0"
```

## What is included

- Core CML audit engine for structured causal records.
- CLI entry point: `cml`.
- Causal chain reconstruction helpers.
- Audit findings for invalid lineage patterns.
- Deterministic safety benchmark fixtures and runner.
- Experimental Cause Band helpers.
- Experimental MCP agent-audit integration path.
- Friendly optional dependency guard for `cml-mcp` when `[mcp]` is not installed.

## Validation evidence

Package validation has passed:

```text
https://github.com/safal207/Causal-Memory-Layer/actions/runs/27063042787/job/79879380002
```

TestPyPI publication and clean install smoke test have passed:

```text
https://github.com/safal207/Causal-Memory-Layer/actions/runs/27069357386
```

Confirmed before production release:

- tests passed,
- deterministic safety benchmark passed,
- package build passed,
- metadata validation passed,
- wheel install validation passed,
- TestPyPI publication passed,
- TestPyPI install smoke test passed,
- `cml --help` worked,
- `import cml` worked,
- MCP core import worked,
- `core.health()` worked.

## Current benchmark snapshot

```text
6/6 matched
```

See:

```text
docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md
```

## Experimental MCP integration

The package includes an experimental MCP path for agent-audit workflows.

Local development:

```bash
pip install -e ".[mcp]"
cml-mcp
```

Packaged install:

```bash
pip install "causal-memory-layer[mcp]==0.4.0"
cml-mcp
```

MCP tool logic includes:

```text
health
audit_trace
evaluate_cause_band
```

## Known limitations

- CML is a focused causal-validity audit prototype, not a complete runtime safety platform.
- Cause Band semantics are experimental and not stable CML/vCML semantics.
- MCP integration is experimental and local-first.
- External validation notes are still being collected.
- The current deterministic benchmark is intentionally small; broader benchmark expansion is future work.
- This release does not provide a hosted service by itself.

## Non-claims

This release does not claim:

- production AI safety,
- regulatory compliance,
- runtime enforcement guarantees,
- complete jailbreak detection,
- complete security coverage,
- stable Cause Band semantics,
- certification readiness,
- future prediction,
- quantum security guarantees.

The correct narrow claim is:

```text
CML 0.4.0 is a package-validated, installable causal-validity audit prototype for structured action traces.
```

## Release docs

Full release notes draft:

```text
docs/release/RELEASE_NOTES_0.4.0.md
```

Production checklist:

```text
docs/release/PRODUCTION_PYPI_RELEASE_CHECKLIST_0.4.0.md
```
