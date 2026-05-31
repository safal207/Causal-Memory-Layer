# Causal Memory Layer (CML)

[![CI](https://github.com/safal207/Causal-Memory-Layer/actions/workflows/ci.yml/badge.svg)](https://github.com/safal207/Causal-Memory-Layer/actions/workflows/ci.yml)
[![Package Validation](https://github.com/safal207/Causal-Memory-Layer/actions/workflows/python-package-validation.yml/badge.svg)](https://github.com/safal207/Causal-Memory-Layer/actions/workflows/python-package-validation.yml)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Audit](https://img.shields.io/badge/audit-causal%20lineage-blue)
![License](https://img.shields.io/badge/license-MIT-orange)
[![Safety Eval](https://img.shields.io/badge/safety--eval-6%2F6%20matched-purple)](docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md)

![CML before-after causal audit visual](docs/assets/cml-before-after.svg)

## Why CML?

**Logs show what happened. CML checks why it was allowed.**

A workflow can pass every functional test and still be causally invalid: the action succeeded, but the approval, intent, or responsibility lineage is missing, ambiguous, or broken.

```text
ordinary log:  action completed -> OK
CML audit:     parent_cause=approval-42 -> MISSING_PARENT
```

CML is an open-source causal audit layer for structured action traces, AI-agent workflows, high-trust automation, and reviewable safety infrastructure.

> A system may be functionally correct while being causally invalid.

**Star this repo if you care about auditable AI agents, deterministic oversight, causal traces, and open-source AI safety infrastructure.**

## 30-second demo

Run the local API:

```bash
docker compose up --build
```

Then follow the Docker walkthrough:

```text
docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md
```

Expected example finding:

```text
CML-AUDIT-R1-MISSING_PARENT
```

The action may look operationally valid, but CML asks whether its causal parent exists.

## Use CML when you need to audit

- AI-agent tool calls and action chains.
- Human approval handoffs.
- Automation workflows with high-trust actions.
- Fintech or review-heavy decision paths.
- Structured traces where responsibility lineage matters.
- Research benchmarks for causal validity in agentic systems.

## How CML differs

| System type | Usually answers | CML adds |
| :--- | :--- | :--- |
| Logs | What happened? | Was the action causally permitted? |
| Tracing | Where did execution go? | Did responsibility lineage survive the workflow? |
| Observability | What failed operationally? | What succeeded but had broken causal lineage? |
| Policy checks | Is this allowed now? | Why was this specific action allowed in this trace? |
| CML | Why was this action allowed? | Narrow audit primitive, not a full runtime safety stack. |

## Fast validation

```bash
pip install -e ".[dev]"
pytest
python scripts/run_safety_eval.py
```

Dashboard:

```text
https://safal207.github.io/Causal-Memory-Layer/
```

## Review links

- Start here: [`docs/START_HERE.md`](docs/START_HERE.md)
- Reviewer path: [`docs/REVIEWER_PATH.md`](docs/REVIEWER_PATH.md)
- Non-claims: [`docs/NON_CLAIMS.md`](docs/NON_CLAIMS.md)
- Portfolio relationship: [`docs/PORTFOLIO_RELATIONSHIP.md`](docs/PORTFOLIO_RELATIONSHIP.md)
- Benchmark evidence: [`docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md`](docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md)
- External validation protocol: [`docs/evidence/EXTERNAL_VALIDATION_PROTOCOL.md`](docs/evidence/EXTERNAL_VALIDATION_PROTOCOL.md)
- Technical report outline: [`docs/research/TECHNICAL_REPORT_OUTLINE.md`](docs/research/TECHNICAL_REPORT_OUTLINE.md)
- Funding / research evidence: [`docs/GRANT_EVIDENCE.md`](docs/GRANT_EVIDENCE.md)
- Docker walkthrough: [`docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md`](docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md)
- Cause Band concept: [`docs/research/CAUSE_BAND.md`](docs/research/CAUSE_BAND.md)
- Experimental Cause Band audit flag: [`docs/experimental/CAUSE_BAND_AUDIT_FLAG.md`](docs/experimental/CAUSE_BAND_AUDIT_FLAG.md)
- Causal invalidity patterns: [`docs/research/CAUSAL_INVALIDITY_PATTERNS.md`](docs/research/CAUSAL_INVALIDITY_PATTERNS.md)
- Audit findings glossary: [`docs/audit/FINDINGS_GLOSSARY.md`](docs/audit/FINDINGS_GLOSSARY.md)
- LTP / CML bridge: [`docs/LTP_CML_BRIDGE.md`](docs/LTP_CML_BRIDGE.md)
- Roadmap: [`ROADMAP.md`](ROADMAP.md)
- Security: [`SECURITY.md`](SECURITY.md)
- License: [`LICENSE`](LICENSE)

## Current artifact

This repository already contains a working technical artifact, not only a concept.

Current components include:

- Python causal validation and audit engine;
- causal chain reconstruction utilities;
- CLI commands for lineage validation and chain inspection;
- API layer and store interface;
- example logs and audit outputs;
- tests for chain logic, audit rules, and CTAG behavior;
- API smoke tests for health, audit, and CTAG decode;
- deterministic safety-eval benchmark with fixtures and tracked results;
- documentation for vCML semantics and audit rules.

Key implementation entry points:

- `cml/audit.py`
- `cml/chain.py`
- `cli/main.py`
- `api/server.py`
- `tests/test_audit.py`
- `tests/test_api_smoke.py`

## Problem

Many systems record events, outputs, traces, and metrics, but do not validate the causal structure behind authorization and action.

That creates blind spots such as:

- actions that appear valid but have no grounded parent cause;
- ambiguous or malformed root authority;
- actions that succeed operationally while losing approval lineage;
- state transitions that cannot be tied back to intent, permission, and responsibility.

For agentic systems, this matters because output review alone can miss causally invalid action chains.

## What CML does

CML checks whether a high-trust action or state transition was causally valid, not only whether it occurred.

It focuses on:

- validating causal links between actions and prior authorization;
- preserving responsibility lineage across multi-step workflows;
- checking intent and permission continuity across transitions;
- detecting suspicious or invalid lineage such as missing parents, malformed roots, or broken handoffs;
- validating causal coherence from structured logs and traces.

## Evidence snapshot

- Deterministic benchmark fixtures with expected audit findings: `benchmarks/fixtures/`
- Current tracked benchmark result: `6/6 matched`
- Benchmark runner: `python scripts/run_safety_eval.py`
- Tracked report: `benchmarks/RESULTS.md`
- Reviewer-friendly benchmark interpretation: `docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md`
- Larger-grant expansion path: `docs/evidence/BENCHMARK_EXPANSION_PLAN_50K_100K.md`
- External validation protocol: `docs/evidence/EXTERNAL_VALIDATION_PROTOCOL.md`

## Repository map

- `cml/`: core Python implementation
- `cli/`: command-line tooling
- `api/`: API and store layer
- `vcml/`: vCML semantics, format, audit, and boundary docs
- `examples/`: sample logs and reports
- `benchmarks/`: deterministic benchmark fixtures and results
- `tests/`: regression coverage
- `docs/`: supporting docs for review, research, and deployment

## Scope

CML does not claim to solve all AI safety, security, or compliance problems.

It contributes one focused primitive:

```text
causal-validity checking for structured action traces
```

See [`docs/NON_CLAIMS.md`](docs/NON_CLAIMS.md) for the full scope boundary.

## Research direction

The strongest research direction for CML is causal validity checking for agentic oversight.

A useful framing is:

> How can we detect actions that appear valid at the surface level but are causally invalid because authorization, approval, or responsibility lineage is missing, ambiguous, or broken?

## Bottom line

A system may be functionally correct while being causally invalid.

CML exists to make that distinction inspectable.
