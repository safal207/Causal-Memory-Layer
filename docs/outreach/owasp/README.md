# OWASP Agentic Security Initiative outreach pack

Status: ready for external review after repository CI.

This pack prepares a focused contribution to the OWASP GenAI Security Project's Agentic Security Initiative (ASI). It does not claim OWASP endorsement, certification, or official alignment.

## Primary target

- Initiative: OWASP Agentic Security Initiative
- Slack: `#team-genai-agentic-security-initiative`
- Open meeting: Agentic Security Working Group, as listed on the current initiative page
- Primary taxonomy: OWASP Top 10 for Agentic Applications 2026 (`ASI01`–`ASI10`)

Official starting points:

- https://genai.owasp.org/initiatives/agentic-security-initiative/
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- https://genai.owasp.org/contribute/

## Ordered causal route

The contribution route is deliberately sequential:

```text
Agentic Security Working Group
-> AI Red Teaming & Evaluation
-> MCP security guidance workstream
-> Agent Memory Guard / ASI06 integration
```

This is a proposed navigation path, not an official OWASP hierarchy. The Agentic Security and Red Teaming entities are public initiatives or working groups. MCP security guidance is a documented workstream, and Agent Memory Guard is a reference implementation.

The detailed cause-space-time-transition analysis is in [`CAUSAL_SPACE_TIME_MAP.md`](CAUSAL_SPACE_TIME_MAP.md). The same model is available as strict machine-readable JSON in [`causal_space_time_map.json`](causal_space_time_map.json).

## Contribution ask

CML is not asking OWASP to adopt a product. The narrow request is:

1. review the ten-scenario Agent Safety Benchmark as an open evaluation artifact;
2. review the proposed crosswalk to ASI01–ASI10;
3. identify missing scenarios or incorrect mappings;
4. advise whether the work best belongs in the Agentic Security Initiative, AI Red Teaming & Evaluation, an AI Testing Guide, AISVS, or another workstream;
5. consider a small interoperability exercise with another agent framework or benchmark harness;
6. review the proposed future MCP supply-chain and persistent-memory scenarios.

## Included material

- [`CROSSWALK.md`](CROSSWALK.md): case-by-case mapping and explicit coverage gaps;
- [`crosswalk.json`](crosswalk.json): machine-readable mapping;
- [`CAUSAL_SPACE_TIME_MAP.md`](CAUSAL_SPACE_TIME_MAP.md): causal, spatial, temporal, and transition analysis;
- [`causal_space_time_map.json`](causal_space_time_map.json): machine-readable 4D navigation model;
- [`SOURCE_SNAPSHOT.md`](SOURCE_SNAPSHOT.md): dated official-source locations and freshness boundary;
- [`SLACK_MESSAGE.md`](SLACK_MESSAGE.md): concise first contact for the Agentic Security channel;
- [`WORKSTREAM_MESSAGES.md`](WORKSTREAM_MESSAGES.md): ordered follow-ups for Red Teaming, MCP security, and Memory Guard;
- [`MEETING_BRIEF.md`](MEETING_BRIEF.md): five-minute working-group presentation.

## Evidence

- One-click MCP recovery evidence: https://safal207.github.io/Causal-Memory-Layer/trust-console/?evidence=mcp&record=mcp_sdk_duplicate_recovered
- Agent Safety Benchmark: https://github.com/safal207/Causal-Memory-Layer/tree/main/benchmarks/agent_safety
- Results: https://github.com/safal207/Causal-Memory-Layer/blob/main/benchmarks/agent_safety/RESULTS.md
- CAEP implementation: https://github.com/safal207/Causal-Memory-Layer/tree/main/docs/experimental/caep
- MCP/SEP outreach pack: https://github.com/safal207/Causal-Memory-Layer/tree/main/docs/outreach/mcp

## Timing rule

1. Publish the primary ASI message first.
2. Follow explicit routing guidance from OWASP contributors.
3. If no routing response arrives after five business days, post the shorter Red Teaming message and link back to the ASI submission.
4. Approach the MCP security workstream only after reviewers identify the tool/MCP scenarios as useful.
5. Approach Agent Memory Guard only when the ASB-12 persistent-memory fixture and adapter are executable.
6. Recheck channel names, meeting schedules, and contribution instructions before every external post.

## Boundaries

The benchmark is deterministic and contract-based. It does not establish real-world incident rates, general model safety, publisher authenticity, production certification, or independent model performance. The crosswalk and organizational route are contribution proposals and must be reviewed by OWASP contributors before being described as OWASP-aligned.

Disclosure: prepared with AI assistance under human direction and review.
