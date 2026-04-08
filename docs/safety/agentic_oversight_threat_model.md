# Agentic Oversight Threat Model

## Purpose

This document explains what kinds of safety-relevant failures Causal Memory Layer (CML) is designed to help detect.

CML is not a complete AI safety system. It is a causal audit layer for checking whether a recorded action was actually grounded in a valid chain of permission, intent, and responsibility.

The main question CML helps answer is:

> Did this action happen through a causally valid and accountable path, or did the system produce a state change that cannot be properly justified by its recorded lineage?

## Why This Matters

In agentic systems, many failures are not obvious from the final output alone.

A tool call, transaction, message, or side effect can look superficially correct while still being unsafe or invalid because:

- the action has no valid parent cause,
- the authorization chain is missing or ambiguous,
- the system crossed a sensitive boundary without a valid lineage,
- the record hides a causal gap,
- or responsibility cannot be reconstructed after the fact.

These are not only observability problems. They are oversight problems.

## Failure Classes CML Can Help Detect

### 1. Missing Parent Reference

A record points to a parent cause that does not exist in the log.

Why it matters:
- the action cannot be traced back to a valid prior cause
- the system may be fabricating or dropping lineage
- accountability is broken

Current rule:
- `R1` reference integrity

### 2. Unmarked Causal Gap

A record has no parent cause, but it is not explicitly marked as an unobserved gap and does not qualify as a valid root event.

Why it matters:
- the system lost causal continuity
- the record may conceal where authority or responsibility disappeared
- the action chain becomes hard to trust

Current rule:
- `R2` gap marking

### 3. Ambiguous Root Authority

A record looks like it is trying to declare a root authority, but the root label is malformed or near-miss.

Why it matters:
- root authority can be spoofed or misrepresented
- the system may appear authorized while using an invalid authority marker
- auditors cannot reliably distinguish legitimate roots from malformed ones

Current rule:
- `R4` ambiguous root detection

### 4. Sensitive Access Followed by Outbound Action Without Valid Lineage

A process accesses a secret or sensitive object and later performs a network action without a valid causal path connecting the two.

Why it matters:
- this is a concrete example of causal invalidity in a potentially high-risk path
- the system may be exfiltrating or exporting sensitive state without a properly recorded justification chain
- output-level review can miss this entirely

Current rule:
- `R3` secret-to-network chain validation

### 5. Policy-Specific Lineage Violations

A record violates a domain-specific rule about what kinds of ancestors must exist before an action is considered valid.

Examples:
- a financial transaction should descend from a session root
- a privileged operation should descend from an approved authorization class
- a boundary-crossing action should descend from a required preceding step

Why it matters:
- many real systems need stronger lineage requirements than generic logging provides
- custom causal constraints make unsafe workflows detectable in a reproducible way

Current mechanism:
- custom audit rules

## What CML Does Not Detect

CML does not, by itself, detect:

- whether a model belief is true or false
- whether an action is morally acceptable in the abstract
- prompt injection content at the semantic language level
- hidden reasoning inside a model if no causal record is emitted
- all forms of runtime compromise or infrastructure abuse

CML is not a replacement for model evaluation, sandboxing, access control, monitoring, or incident response.

## Where CML Fits in a Safety Stack

A practical safety stack may include:

- policy and access control
- runtime containment and tool gating
- trace inspection and output evaluation
- causal audit of recorded action lineage
- post-hoc forensics and incident review

CML fits in the causal audit and accountability layer.

Its strength is not broad semantic judgment. Its strength is making authorization and responsibility lineage inspectable.

## Research Framing

A strong research framing for CML is:

> How can we detect actions that appear valid at the surface level but are causally invalid because the recorded chain of authorization, approval, or responsibility is missing, malformed, or broken?

This makes CML especially relevant as supporting infrastructure for:

- agentic oversight
- safety evaluation
- accountability-preserving action systems
- high-stakes workflow auditing

## Bottom Line

CML helps expose a specific kind of failure:

A system may produce an apparently valid action while lacking a causally valid path that explains why it was permitted to happen.

That is the failure class CML is built to make visible.
