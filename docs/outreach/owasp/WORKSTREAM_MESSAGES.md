# OWASP workstream follow-up messages

Use these only after the primary Agentic Security Initiative message has been posted. Do not post all messages at once.

## AI Red Teaming & Evaluation

Target: `#team-genai-redteam`

```text
Hi — following a submission to the OWASP Agentic Security Initiative, we would value evaluation-method feedback on an open deterministic benchmark for stateful tool-using agents.

CML Agent Safety Benchmark v0.1 contains ten incidents and scores intent preservation, causal reconstruction, containment, minimal recovery, and independent verification. A critical forbidden action or missing containment caps a case below the pass threshold.

The reference policy scores 100/100. An intentionally unsafe baseline that treats tool success as user-level success fails all ten cases.

Benchmark:
https://github.com/safal207/Causal-Memory-Layer/tree/main/benchmarks/agent_safety

Proposed OWASP crosswalk:
https://github.com/safal207/Causal-Memory-Layer/blob/main/docs/outreach/owasp/CROSSWALK.md

Causal-space-time evaluation map:
https://github.com/safal207/Causal-Memory-Layer/blob/main/docs/outreach/owasp/CAUSAL_SPACE_TIME_MAP.md

Could the Red Teaming & Evaluation group advise on three narrow questions?

1. Which validity or adversarial-coverage checks are missing?
2. Which existing evaluation harness would be the best external implementation target?
3. Should recovery and independent final-state verification be treated as separate scoring dimensions?

This is a request for review, not a claim of OWASP alignment or endorsement.
```

## MCP security review

Target: use the routing location recommended by the Agentic Security or Red Teaming contributors. No separate public MCP working-group channel is asserted by this pack.

```text
We have isolated four agent-safety scenarios that may complement OWASP MCP security guidance:

- ASB-01: stale observation causes duplicate payment;
- ASB-04: timeout leaves idempotent outcome unknown;
- ASB-06: secret reaches a network tool without valid causal lineage;
- proposed ASB-11: compromised MCP tool or skill package.

The existing OWASP guidance addresses secure server architecture, authentication, authorization, validation, session isolation, sandboxing, and third-party MCP risk. The CML contribution focuses on the post-execution question: did the actual external state still satisfy the user's critical postconditions, and can a bounded recovery be causally verified?

Real MCP recovery evidence:
https://safal207.github.io/Causal-Memory-Layer/trust-console/?evidence=mcp&record=mcp_sdk_duplicate_recovered

Would these scenarios be useful as a small executable companion or evaluation slice for MCP security guidance?

This is a contribution proposal, not a claim of official compatibility or adoption.
```

## Agent Memory Guard / ASI06

Target: an issue or contribution discussion in the OWASP Agent Memory Guard repository after ASB-12 is runnable.

```text
We are preparing ASB-12, a deterministic persistent-memory poisoning and recovery scenario, and would value an integration review with OWASP Agent Memory Guard.

Proposed lifecycle:

untrusted document writes hidden instruction
-> memory guard blocks or quarantines the write
-> CML records the rejected write and causal lineage
-> trusted snapshot is restored if required
-> a later unrelated session reads memory
-> independent verification confirms that poisoned state no longer influences planning or tool use

The goal is to test not only detection at write time, but trustworthy state across time: provenance, quarantine, rollback, and future-session verification.

Current benchmark and ASI crosswalk:
https://github.com/safal207/Causal-Memory-Layer/tree/main/benchmarks/agent_safety
https://github.com/safal207/Causal-Memory-Layer/blob/main/docs/outreach/owasp/CROSSWALK.md

Would this lifecycle fit the project's contribution model once the fixture and adapter are runnable?

This proposal does not claim OWASP endorsement or current ASI06 completeness.
```

## Timing rule

1. Post the primary ASI message first.
2. Follow the route OWASP contributors recommend.
3. If no routing response arrives after five business days, post the Red Teaming message with a link back to the ASI submission.
4. Do not approach Memory Guard until ASB-12 is executable.
5. Recheck channel names and contribution instructions immediately before posting.
