# Causal Memory Layer (CML)

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Audit](https://img.shields.io/badge/audit-causal%20lineage-blue)
![License](https://img.shields.io/badge/license-MIT-orange)

**Project status:** Active development with test coverage and CI validation for core audit semantics.

**Fast validation (under 2 minutes):**
```bash
pip install -e ".[dev]"
pytest
```

## Review Links
- Architecture: `docs/`
- Validation: `pytest`
- Security: `SECURITY.md`
- Roadmap: `ROADMAP.md`
- License: `LICENSE`

Causal Memory Layer is an open-source causal audit layer for checking whether a sensitive action was actually grounded in a valid chain of permission, intent, and responsibility.

It checks whether an action that appears operationally correct is backed by valid authorization lineage and preserves responsibility across steps. CML is designed for settings where knowing what happened is not enough; we also need to know why it was allowed to happen.

The core idea is central: a system may be functionally correct while being causally invalid. An action may succeed, a response may look reasonable, and a workflow may complete, but the underlying chain can still be causally unauthorized, missing parent approval, hiding a causal gap, or failing responsibility preservation across steps.

This makes CML relevant to high-risk AI workflows, agentic oversight, fintech controls, security auditing, and safety evaluation.

## Example: 5-hop QA Causal Mismatch (A→B vs A→C)

In one of the first experiments with CML, I used it as a causal validity layer on top of a 5-hop QA task over an internal knowledge graph.

The model had to answer a question that required following a chain of facts A→B→…→Z. On the 4th hop it started to "correct" the intermediate fact and silently replaced the required edge A→B with a more plausible A→C that did not exist in the graph.

CML was running as a read-only validator over the event trace. For this query it showed no causal link through the required B edge, while tracing a clean path through the incorrect C edge. In other words, the textual reasoning trace looked fine, but the recorded causal chain had diverged from the authorization lineage that was supposed to ground the answer.

This is exactly the class of failures CML is designed to surface: cases where the model produces a plausible chain-of-thought that is causally disconnected from the authorization lineage that was supposed to ground the answer. The audit log for this run is in `examples/multihop_qa_mismatch_log.jsonl` and a walkthrough of how the mismatch shows up in chain reconstruction is in `examples/multihop_qa_mismatch_explain.md`.

## Application-Ready Summary

Use this framing in grant or fellowship applications:

- CML detects actions that look valid at output level but are causally invalid in lineage.
- CML provides deterministic, reproducible audit checks instead of narrative-only review.
- CML contributes one concrete safety primitive: causal validity testing for authorization and responsibility chains.

## Problem

Many systems record events, outputs, traces, and metrics, but do not validate the causal structure behind authorization and action.

That creates blind spots such as:

- actions that appear valid but have no grounded parent cause
- ambiguous or malformed root authority
- causally unauthorized privileged actions that still succeed operationally
- sensitive access followed by outbound behavior without a valid lineage
- state transitions that cannot be tied back to intent, permission, and responsibility

For agentic systems, this matters because output review alone can miss unsafe or causally invalid action chains.

## What CML Does

CML checks whether a sensitive action or state transition was causally valid, not only whether it occurred.

It focuses on:

- validating causal links between actions and prior authorization
- preserving responsibility lineage across multi-step workflows
- checking intent and permission continuity across transitions
- detecting suspicious or invalid lineage (missing parents, malformed roots, broken handoffs)
- validating causal coherence from structured logs and traces

In practical terms, CML is a causal validity and authorization-lineage primitive that can support audit and accountability workflows.

## Why This Matters for Agentic Systems

Agentic systems can produce actions that appear reasonable or successful while lacking valid causal grounding. CML exists to make those failures inspectable.

Examples:

- a privileged action has no valid parent authorization
- a root authority label is malformed or ambiguous
- a secret access and a network action occur in the same process without valid causal lineage
- a workflow contains an unmarked causal gap where responsibility was lost

CML helps identify actions that are operationally successful but causally unauthorized.

It is not a full safety stack on its own. It is one validation primitive that checks whether recorded action lineage is causally valid and responsibility-preserving.

## Current Artifact

This repository already contains a working technical artifact, not only a concept.

Current components include:

- a Python causal validation and audit engine
- causal chain reconstruction utilities
- CLI commands for lineage validation and chain inspection
- a small API layer and store interface
- example logs and example audit outputs
- tests for chain logic, audit rules, and CTAG behavior
- a deterministic safety-eval benchmark with fixtures and tracked results
- documentation for vCML semantics and audit rules

Key implementation entry points:

- `cml/audit.py`
- `cml/chain.py`
- `cli/main.py`
- `api/server.py`
- `tests/test_audit.py`

## Threat Model Fit

CML is best understood as infrastructure for causal validity checking of sensitive actions.

It is useful for evaluating or auditing failures such as:

- missing parent authorization references
- unmarked causal gaps
- ambiguous root authority
- secret-to-network paths without valid causal linkage
- broken responsibility lineage across handoffs
- policy-specific authorization-lineage violations expressed as custom rules

This repository does not claim to solve all AI safety problems. It contributes a specific control primitive: checking causal validity through authorization lineage, intent continuity, and responsibility preservation.

## Scope

### In Scope

- immutable records of intent, permission, and responsibility
- explicit causal links between effects and prior causes
- semantics for validating causal validity and authorization-lineage coherence
- language-agnostic and transport-agnostic causal validity concepts

### Out of Scope

- transport
- execution
- infrastructure orchestration
- storage engine mechanics
- model alignment as a whole

CML does not execute code or enforce runtime policy by itself. It validates whether recorded action chains are causally valid and responsibility-preserving.

## Differentiation

| System Type | Focus | CML Difference |
| :--- | :--- | :--- |
| Logs / access events | What happened | CML checks whether what happened was causally permitted and properly authorized. |
| Tracing (OpenTelemetry) | Execution order, latency, performance | Tracing explains execution flow. CML checks causal validity of authorization lineage. |
| Execution (Lambda, K8s, jobs) | Running tasks | CML is not the executor; it validates authorization lineage behind sensitive actions. |
| Transport (HTTP, TCP) | Moving data | CML does not focus on delivery; it focuses on authorization lineage and responsibility preservation across sensitive transitions. |

## Quick Start

Run tests:

```bash
python -m pytest -q
```

Run deterministic safety benchmark:

```bash
python scripts/run_safety_eval.py
```

Inspect example logs through the current Python tooling and examples in:

- `examples/exec_causal_log.jsonl`
- `examples/secret_to_net_log.jsonl`
- `examples/secret_to_net_explain.md`
- `benchmarks/README.md`
- `benchmarks/RESULTS.md`

## Evidence Snapshot

- Deterministic safety benchmark fixtures with expected audit findings (`benchmarks/fixtures/`)
- Covered failure classes: valid chain, missing parent, unmarked gap, ambiguous root, secret-to-network without valid lineage, custom policy violation
- Reproducible benchmark run command: `python scripts/run_safety_eval.py`
- Tracked benchmark report: `benchmarks/RESULTS.md`

## Repository Map

- `cml/`: core Python implementation
- `cli/`: command-line tooling
- `api/`: store and server layer
- `vcml/`: semantics, format, audit, and boundary documentation
- `examples/`: sample logs and reports
- `tests/`: regression coverage
- `docs/`: wiki, SDK, enterprise, and scenario docs

## Research Direction

The strongest research direction for CML is causal validity checking for agentic oversight.

A useful framing is:

> How can we detect actions that appear valid at the surface level but are causally invalid because authorization, approval, or responsibility lineage is missing, ambiguous, or broken?

That makes CML a strong supporting artifact for safety evaluation work focused on causal validity, authorization lineage, and responsibility-preserving action chains.

## Bottom Line

A system may be functionally correct while being causally invalid.

CML exists to make that distinction inspectable.
