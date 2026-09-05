# OWASP Agentic Security causal-space-time map

Verified against official public sources on 2026-08-01.

This document is a proposed navigation model for contributing the CML Agent Safety Benchmark to the OWASP GenAI Security Project. It is not an official OWASP organizational chart and does not claim endorsement, certification, or adoption.

## Method

The map uses four dimensions:

1. **Cause** — what condition creates the unsafe transition;
2. **Space** — where authority, state, memory, tools, or verification live;
3. **Time** — when a system state becomes trusted, uncertain, contained, recovered, or persistent;
4. **Transition** — what guard permits movement from one state to the next.

Only entities explicitly named by OWASP as initiatives or working groups are classified as organizational groups. Guides, taxonomies, and reference implementations are classified as workstreams or artifacts.

## Organizational graph

```text
Agentic Security Working Group
#team-genai-agentic-security-initiative
        |
        | routes evaluation-method questions
        v
AI Red Teaming & Evaluation
#team-genai-redteam
        |
        | applies adversarial methodology to tool-using agents
        v
MCP security guidance workstream
        |
        | narrows persistent-state risk
        v
OWASP Agent Memory Guard
ASI06 reference implementation
```

### Official group versus workstream

| Node | Classification | Why it matters to CML |
|---|---|---|
| Agentic Security Working Group | Official working group | Primary review and routing point for the ASI01–ASI10 crosswalk and benchmark contribution. |
| AI Red Teaming & Evaluation | Official initiative | Best home for evaluation rigor, adversarial methodology, external harnesses, and benchmark repeatability. |
| MCP security guidance | Documented workstream | Connects CML evidence to delegated permissions, chained tools, validation, session isolation, and third-party MCP risk. |
| Agent Memory Guard | Reference implementation | Natural integration target for a persistent-memory poisoning and recovery scenario. |

## Causal graph

```text
Unsafe input, stale state, revoked authority, or poisoned memory
        v
Agent selects or repeats a tool action
        v
Tool response appears successful
        v
External business state may still violate user intent
        v
Independent verification detects divergence or uncertainty
        v
Contain further actions
        v
Execute the smallest bounded recovery
        v
Independently verify the restored state
        v
Provenance-check persistent context before future reuse
```

The distinctive CML contribution is not another risk taxonomy. It is a deterministic contract for the edges between states:

```text
intent -> causality -> containment -> recovery -> independent verification
```

## Spatial graph

### 1. Intent space

Question: **What user objective must remain invariant?**

CML evidence:

- intent code and summary;
- constraints;
- expected postconditions;
- initiator and request reference.

Primary OWASP relation: ASI01, ASI09.

### 2. Authority space

Question: **Who may authorize this transition now?**

CML evidence:

- current authorization decision;
- scope and expiry;
- approval and policy references;
- actor identity.

Primary OWASP relation: ASI03, ASI07, ASI10.

### 3. Tool and MCP space

Question: **Which exact server and tool caused the side effect?**

CML evidence:

- tool name and schema digest;
- server and executor references;
- request digest, idempotency key, and correlation ID;
- started and completed times.

Primary OWASP relation: ASI02, ASI04, ASI05.

### 4. External-state space

Question: **What changed outside the model?**

CML evidence:

- state-before and state-after digests;
- observed outcome;
- critical business postconditions.

Primary OWASP relation: ASI02, ASI08, ASI09.

### 5. Verification space

Question: **Did an independent observer confirm the user-level invariant?**

CML evidence:

- independent verifier identity;
- per-postcondition checks;
- verified, diverged, or inconclusive verdict.

Primary OWASP relation: ASI08, ASI09.

### 6. Recovery space

Question: **Which bounded transition restored trust?**

CML evidence:

- containment status;
- compensating action;
- causal-parent identifiers and digest bindings;
- second independent verification.

Primary OWASP relation: ASI08, ASI10.

### 7. Persistent-memory space

Question: **Can an untrusted write influence a later session?**

Required future CML evidence:

- memory-write provenance;
- quarantine or block decision;
- trusted snapshot and rollback;
- independently verified future read.

Primary OWASP relation: ASI06.

## Time-state graph

```text
T0 declared intent
 |
 v
T1 plan and preconditions
 |
 v
T2 current authorization
 |
 v
T3 tool dispatch
 |
 v
T4 observed external effect
 |
 v
T5 independent verification
 |                    |
 | pass               | divergence / uncertainty
 v                    v
T8 verified       T6 containment
final state           |
                      v
                  T7 minimal recovery
                      |
                      v
                  T8 verified final state
                      |
                      v
                  T9 future session or reuse
```

### Transition guards

| Transition | Required guard |
|---|---|
| T0 -> T1 | Plan preserves declared constraints. |
| T1 -> T2 | Authority is current and scoped. |
| T2 -> T3 | Dispatch is the smallest authorized side effect. |
| T3 -> T4 | Record the actual external outcome, not tool wording alone. |
| T4 -> T5 | An independent verifier checks critical postconditions. |
| T5 -> T8 | Every critical check passes. |
| T5 -> T6 | Divergence or uncertainty is detected and further harm is blocked. |
| T6 -> T7 | Recovery is bounded, reversible where possible, and causally parent-bound. |
| T7 -> T8 | Independent verification confirms restoration. |
| T8 -> T9 | Persistent context is provenance-checked before reuse. |

## Ordered contribution route

### State R0 — package prepared

Existing evidence:

- ten-scenario Agent Safety Benchmark;
- ASI01–ASI10 proposed crosswalk;
- real MCP divergence, containment, recovery, and verification evidence;
- explicit v0.1 gaps and v0.2 scenario proposals.

### Transition R0 -> R1 — Agentic Security Working Group

Action:

- publish the primary message in `#team-genai-agentic-security-initiative`;
- ask for mapping corrections and routing advice;
- offer a five-minute working-group presentation.

Completion evidence:

- Slack post reference or meeting agenda/recording reference.

### Transition R1 -> R2 — Red Teaming & Evaluation

Trigger:

- ASI confirms evaluation relevance; or
- no routing response after five business days.

Action:

- post a shorter evaluation-method request in `#team-genai-redteam`;
- ask for benchmark validity, adversarial coverage, and external harness feedback.

### Transition R2 -> R3 — MCP security workstream

Trigger:

- reviewers identify tool and MCP scenarios as a useful evaluation slice.

Action:

- propose ASB-01, ASB-04, ASB-06, and future ASB-11 as an MCP security evaluation bundle;
- connect secure configuration guidance to post-execution evidence and independent business-state verification.

### Transition R3 -> R4 — Memory Guard

Trigger:

- ASB-12 persistent-memory poisoning fixture and adapter are runnable.

Action:

- open an issue or PR proposing an integration exercise:

```text
untrusted memory write
-> Memory Guard blocks or quarantines
-> CML records causal lineage
-> trusted snapshot is restored
-> future-session read is independently verified
```

## Decision logic

```text
Does the question concern ASI risk mapping or agentic governance?
-> Agentic Security Working Group

Does it concern benchmark rigor, red-team methodology, or evaluation tooling?
-> AI Red Teaming & Evaluation

Does it concern tool servers, delegated permissions, chained calls, or third-party MCP risk?
-> MCP security workstream

Does it concern persistent cross-session state and rollback?
-> Agent Memory Guard
```

## Current gaps that control the route

- **ASI04:** no dedicated compromised MCP tool, registry, skill, or dependency provenance scenario;
- **ASI05:** no sandbox-boundary arbitrary-execution scenario;
- **ASI06:** no runnable cross-session persistent-memory fixture yet;
- **ASI10:** no persistent rogue behavior, concealment, or self-preservation fixture.

These gaps are not weaknesses to hide. They are the causal bridge to the next four benchmark scenarios.

## Official sources

- Agentic Security Initiative: https://genai.owasp.org/initiatives/agentic-security-initiative/
- AI Red Teaming & Evaluation: https://genai.owasp.org/initiatives/genai-red-teaming-initiative/
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Secure MCP Server Development: https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/
- Securely Using Third-Party MCP Servers: https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/
- Agent Memory Guard: https://github.com/OWASP/www-project-agent-memory-guard
- Memory attack-surface analysis: https://genai.owasp.org/2026/05/13/memory-is-a-feature-it-is-also-an-attack-surface/

Machine-readable map: [`causal_space_time_map.json`](causal_space_time_map.json).
