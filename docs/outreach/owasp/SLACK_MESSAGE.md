# Slack submission

Target channel: `#team-genai-agentic-security-initiative`

```text
Hi everyone — we have built an open, deterministic Agent Safety Benchmark and would value ASI community review rather than claiming alignment ourselves.

The benchmark evaluates ten stateful tool-using-agent incidents across five dimensions:

- intent preservation;
- causal reconstruction;
- containment;
- minimal recovery;
- independent verification of the final state.

It includes payment duplication from stale state, revoked authorization, tool-success/business-failure divergence, uncertain timeout outcomes, retrieved prompt injection, secret egress, multi-agent authority confusion, coding-agent semantic regression, ambiguous recipients, and over-broad recovery.

We prepared a proposed case-by-case crosswalk to the OWASP Top 10 for Agentic Applications 2026. The mapping is intentionally honest about gaps: v0.1 has no dedicated ASI04 supply-chain scenario, and only partial coverage for persistent ASI06 memory poisoning, ASI05 code-execution boundaries, and ASI10 persistent rogue behavior. We have drafted four v0.2 scenarios to close those gaps.

Crosswalk:
https://github.com/safal207/Causal-Memory-Layer/blob/main/docs/outreach/owasp/CROSSWALK.md

Benchmark:
https://github.com/safal207/Causal-Memory-Layer/tree/main/benchmarks/agent_safety

One-click real MCP recovery evidence:
https://safal207.github.io/Causal-Memory-Layer/trust-console/?evidence=mcp&record=mcp_sdk_duplicate_recovered

Our narrow questions are:

1. Are the proposed ASI mappings reasonable?
2. Which missing scenarios would be most valuable to ASI practitioners?
3. Would this fit best as an Agentic Security Initiative evaluation artifact, an AI Testing Guide contribution, an AISVS companion, or another OWASP workstream?
4. Would anyone be interested in a small interoperability exercise using another agent framework or evaluation harness?

The reference policy scores 100/100; an intentionally unsafe baseline that equates tool success with user-level success fails all ten cases. The benchmark does not claim OWASP endorsement, production certification, general model safety, or independent model performance.

Happy to present the crosswalk and live evidence in five minutes at an open working-group meeting.

Disclosure: the implementation and this message were prepared with AI assistance under human direction and review.
```
