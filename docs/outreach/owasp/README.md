# OWASP Agentic Security Initiative outreach pack

Status: ready for external review after repository CI.

This pack prepares a focused contribution to the OWASP GenAI Security Project's Agentic Security Initiative (ASI). It does not claim OWASP endorsement, certification, or official alignment.

## Target

- Initiative: OWASP Agentic Security Initiative
- Slack: `#team-genai-agentic-security-initiative`
- Open meeting: Agentic Security Working Group, Tuesdays, as listed on the initiative page
- Primary taxonomy: OWASP Top 10 for Agentic Applications 2026 (`ASI01`–`ASI10`)

Official starting points:

- https://genai.owasp.org/initiatives/agentic-security-initiative/
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- https://genai.owasp.org/contribute/

## Contribution ask

CML is not asking OWASP to adopt a product. The narrow request is:

1. review the ten-scenario Agent Safety Benchmark as an open evaluation artifact;
2. review the proposed crosswalk to ASI01–ASI10;
3. identify missing scenarios or incorrect mappings;
4. advise whether the work best belongs in the Agentic Security Initiative, the AI Testing Guide, AISVS, or a related working group;
5. consider a small interoperability exercise with another agent framework or benchmark harness.

## Included material

- [`CROSSWALK.md`](CROSSWALK.md): case-by-case mapping and explicit coverage gaps;
- [`crosswalk.json`](crosswalk.json): machine-readable mapping;
- [`SLACK_MESSAGE.md`](SLACK_MESSAGE.md): concise first contact;
- [`MEETING_BRIEF.md`](MEETING_BRIEF.md): five-minute working-group presentation.

## Evidence

- One-click MCP recovery evidence: https://safal207.github.io/Causal-Memory-Layer/trust-console/?evidence=mcp&record=mcp_sdk_duplicate_recovered
- Agent Safety Benchmark: https://github.com/safal207/Causal-Memory-Layer/tree/main/benchmarks/agent_safety
- Results: https://github.com/safal207/Causal-Memory-Layer/blob/main/benchmarks/agent_safety/RESULTS.md
- CAEP implementation: https://github.com/safal207/Causal-Memory-Layer/tree/main/docs/experimental/caep
- MCP/SEP outreach pack: https://github.com/safal207/Causal-Memory-Layer/tree/main/docs/outreach/mcp

## Boundaries

The benchmark is deterministic and contract-based. It does not establish real-world incident rates, general model safety, publisher authenticity, production certification, or independent model performance. The crosswalk is a contribution proposal and must be reviewed by OWASP contributors before being described as OWASP-aligned.

Disclosure: prepared with AI assistance under human direction and review.
