# Release Notes Draft — `causal-memory-layer` 0.4.0

**Status:** release notes draft / not yet published to PyPI  
**Package:** `causal-memory-layer`  
**Version:** `0.4.0`  
**Release track:** first PyPI planning candidate

## Summary

`causal-memory-layer` 0.4.0 is the first package-validation-ready release candidate for CML.

CML is an open-source causal audit layer for structured action traces. It focuses on detecting causally invalid action chains, such as missing parent causes, broken responsibility lineage, malformed roots, and actions that appear operationally valid while lacking a valid causal permission path.

This release candidate packages the current CML core, CLI, API modules, deterministic safety benchmark, experimental Cause Band helpers, and the experimental MCP agent-audit integration path.

## Positioning

A concise framing for this release:

```text
Logs show what happened. CML checks why it was allowed.
```

This release should be presented as:

```text
a reproducible open-source causal audit prototype for structured action traces and AI-agent workflows
```

It should not be presented as production-certified safety infrastructure.

## Highlights

### Core CML audit package

- Python package: `causal-memory-layer`
- CLI entry point: `cml`
- Core audit engine for structured causal records
- Causal chain reconstruction helpers
- Audit findings for invalid lineage patterns
- vCML / CML documentation and review path

### Deterministic benchmark evidence

- Benchmark fixtures under `benchmarks/fixtures/`
- Safety-eval runner:

```bash
python scripts/run_safety_eval.py
```

- Current tracked benchmark result:

```text
6/6 matched
```

### Package validation evidence

Package validation has passed through GitHub Actions:

```text
https://github.com/safal207/Causal-Memory-Layer/actions/runs/27063042787/job/79879380002
```

Confirmed successful workflow steps include:

- install validation tools,
- install package with dev extras,
- run tests,
- run deterministic safety benchmark,
- build source and wheel distributions,
- validate package metadata,
- install built wheel in a fresh environment.

### Experimental MCP agent-audit integration

This release candidate includes an experimental MCP integration path:

- MCP server entry point:

```bash
cml-mcp
```

- MCP optional extra:

```bash
pip install "causal-memory-layer[mcp]"
```

- Local development install:

```bash
pip install -e ".[mcp]"
```

- MCP core tools:

```text
health
audit_trace
evaluate_cause_band
```

The `cml-mcp` entry point now has a friendly optional-dependency guard. If the package is installed without `[mcp]`, it exits with code `2` and explains how to install MCP support.

### MCP demo runner

The release candidate includes a local demo runner for MCP tool logic:

```bash
python scripts/run_mcp_demo_payloads.py
```

Expected sections:

```text
health
audit_trace
evaluate_cause_band
```

### Experimental Cause Band helpers

Cause Band remains experimental.

Included work supports the research direction:

```text
Cause = range deviation over time
```

Current experimental helpers include:

- Cause Band evaluation fixtures,
- trajectory diagnostics,
- recovery / oscillation diagnostics,
- sidecar payload extraction via packaged `cml.experimental.cause_band_payload`.

## Installation draft

After publication to PyPI, expected basic install:

```bash
pip install causal-memory-layer
```

Then:

```bash
cml --help
```

For MCP support:

```bash
pip install "causal-memory-layer[mcp]"
cml-mcp
```

## Validation commands

The package validation path checks:

```bash
python -m pip install --upgrade pip build twine
pip install -e ".[dev]"
pytest
python scripts/run_safety_eval.py
python -m build
python -m twine check dist/*
python -m venv .venv-wheel
. .venv-wheel/bin/activate
python -m pip install --upgrade pip
pip install dist/*.whl
cml --help
python - <<'PY'
import cml
from cml.integrations.mcp import core
print("cml import ok")
print(core.health())
PY
```

The workflow also verifies that `cml-mcp` without `[mcp]` produces the friendly optional-extra message.

## Known limitations

- Not yet published to PyPI at the time of this draft.
- Cause Band semantics are experimental and not stable CML/vCML semantics.
- MCP integration is experimental and local-first.
- External validation notes are still being collected.
- The current benchmark is deterministic and small; broader benchmark expansion is future work.
- This release does not provide hosted service capability by itself.

## Non-claims

This release must not be described as proving:

- production AI safety,
- complete jailbreak detection,
- runtime enforcement,
- regulatory compliance,
- complete security coverage,
- stable Cause Band semantics,
- certification readiness,
- future prediction,
- quantum security guarantees.

The correct claim is narrower:

```text
The package can be built, checked, installed from a wheel, imported, and invoked reproducibly, and it provides a focused causal-validity audit prototype for structured action traces.
```

## Pre-publication checklist

Before publishing this release to PyPI:

- [x] Package validation workflow passes.
- [x] Wheel install validation passes.
- [x] `cml --help` works after wheel install.
- [x] MCP core import works without `[mcp]`.
- [x] `cml-mcp` optional-extra guard is validated.
- [ ] Decide whether to publish `0.4.0` or bump to a new version before first publication.
- [ ] Confirm PyPI or TestPyPI publishing credentials / trusted publishing setup.
- [ ] Optionally perform TestPyPI dry run.
- [ ] Create GitHub release notes from this draft.
- [ ] Publish only with explicit non-claims.

## Suggested GitHub release title

```text
causal-memory-layer 0.4.0 — package-validation-ready CML prototype
```

## Suggested short release description

```text
First package-validation-ready release candidate for CML: a causal audit prototype for structured action traces, with CLI packaging, deterministic benchmark evidence, experimental Cause Band helpers, and experimental MCP agent-audit integration.
```
