# Causal Memory Layer (CML)

Causal Memory Layer is an audit and accountability layer for checking whether a sensitive action was actually grounded in a valid causal chain of permission, intent, and responsibility.

The core idea is simple: a system can be functionally correct at the output level while still being causally invalid. An action may succeed, a response may look reasonable, and a workflow may complete, but the underlying chain can still be missing approval, hiding a causal gap, or failing to preserve responsibility across steps.

This makes CML relevant to AI safety, agentic oversight, fintech controls, security auditing, and other settings where it is not enough to know what happened. You also need to know why it was allowed to happen.

## Example: 5-hop QA Causal Mismatch (A→B vs A→C)

In one of the first experiments with CML, I used it as a causal audit layer on top of a 5-hop QA task over an internal knowledge graph.

The model had to answer a question that required following a chain of facts A→B→…→Z. On the 4th hop it started to "correct" the intermediate fact and silently replaced the required edge A→B with a more plausible A→C that did not exist in the graph.

CML was running as a read-only audit layer over the event trace. For this query it showed no causal link through the required B edge, while tracing a clean path through the incorrect C edge. In other words, the textual reasoning trace looked fine, but the recorded causal chain had drifted away from the ground-truth path.

This is exactly the class of failures CML is designed to surface: cases where the model produces a plausible chain-of-thought that is causally disconnected from the authorized path that was supposed to ground the answer. The audit log for this run is in `examples/multihop_qa_mismatch_log.jsonl` and a walkthrough of how the mismatch shows up in chain reconstruction is in `examples/multihop_qa_mismatch_explain.md`.

## Problem

Many systems record events, outputs, traces, and metrics, but do not preserve the causal structure behind authorization and action.

That creates blind spots such as:

- actions that appear valid but have no grounded parent cause
- ambiguous or malformed root authority
- causal gaps that are not marked explicitly
- sensitive access followed by outbound behavior without a valid lineage
- state transitions that cannot be tied back to intent or permission

For agentic systems, this matters because output review alone can miss unsafe or causally invalid action chains.

## What CML Does

CML records why a state change was permitted, not only that it occurred.

It focuses on:

- causal links between actions and prior authorization
- accountability and responsibility preservation
- audit rules for detecting invalid or suspicious lineage
- read-only validation of causal coherence in structured logs

In practical terms, CML is a causal audit layer.

## Why This Matters for Agentic Oversight

In agentic systems, a final answer or tool result may look acceptable even when the underlying action chain is not.

Examples:

- a privileged action has no valid parent authorization
- a root authority label is malformed or ambiguous
- a secret access and a network action occur in the same process without a valid causal chain
- a workflow contains an unmarked causal gap that hides where responsibility was lost

CML helps make these failures legible.

It is not a full safety stack on its own. It is one layer that checks whether the recorded action lineage is causally valid and accountable.

## Current Artifact

This repository already contains a working technical artifact, not only a concept.

Current components include:

- a Python causal audit engine
- causal chain reconstruction utilities
- CLI commands for audit and chain inspection
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

CML is best understood as infrastructure for detecting causally invalid action chains.

It is useful for evaluating or auditing failures such as:

- missing parent references
- unmarked causal gaps
- ambiguous root authority
- secret-to-network paths without valid causal linkage
- policy-specific lineage violations expressed as custom rules

This repository does not claim to solve all AI safety problems. It contributes a specific audit primitive: checking whether actions were causally grounded in valid permission and responsibility chains.

## Scope

### In Scope

- immutable records of intent, permission, and responsibility
- explicit causal links between effects and prior causes
- audit semantics for validating causal coherence
- language-agnostic and transport-agnostic causal audit concepts

### Out of Scope

- transport
- execution
- infrastructure orchestration
- storage engine mechanics
- model alignment as a whole

CML does not execute code or enforce runtime policy by itself. It records and audits causal structure.

## Differentiation

| System Type | Focus | CML Difference |
| :--- | :--- | :--- |
| Transport (HTTP, TCP) | Moving data | CML cares about the meaning and authorization lineage, not delivery. |
| Tracing (OpenTelemetry) | Performance and debugging | Tracing records what happened. CML records why it was permitted to happen. |
| Execution (Lambda, K8s, jobs) | Running tasks | CML is the memory and audit layer of execution, not the executor. |
| Access logs | Surface events | CML preserves causal linkage and responsibility across steps. |

## Quick Start

Run tests:

```bash
python -m pytest -q
```

Inspect example logs through the current Python tooling and examples in:

- `examples/exec_causal_log.jsonl`
- `examples/secret_to_net_log.jsonl`
- `examples/secret_to_net_explain.md`
- `benchmarks/README.md`
- `benchmarks/RESULTS.md`

## Repository Map

- `cml/`: core Python implementation
- `cli/`: command-line tooling
- `api/`: store and server layer
- `vcml/`: semantics, format, audit, and boundary documentation
- `examples/`: sample logs and reports
- `tests/`: regression coverage
- `docs/`: wiki, SDK, enterprise, and scenario docs

## Research Direction

The strongest research direction for CML is causal audit for agentic oversight.

A useful framing is:

> How can we detect actions that appear valid at the surface level but are causally invalid because authorization, approval, or responsibility lineage is missing, ambiguous, or broken?

That makes CML a strong supporting artifact for safety evaluation work focused on trace validity, authorization lineage, and accountability-preserving action chains.

## Bottom Line

A system may be functionally correct while being causally invalid.

CML exists to make that distinction inspectable.
