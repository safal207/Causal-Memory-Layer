# Proposed README section: For LLM Agents & Grok / xAI systems

Insert this section after the existing approval-lineage demo in the root
`README.md`.

---

## For LLM Agents & Grok / xAI systems

CML can map modern tool-calling workflows into reviewable causal records while
keeping provider-specific metadata inside the stable JSON-compatible
`CausalRecord.object` payload.

Run the SDK-independent demo:

```bash
python examples/grok_xai_causal_audit.py
```

The demo simulates web search, sandbox code execution, a local file write, and
an external API call. Each tool call carries:

- `parent_cause` lineage;
- a concise `intent_description`;
- `risk_level`;
- human-approval state;
- a deterministic `evidence_bundle`;
- CTAG-based action classification.

It prints an invalid and a valid trace and demonstrates findings such as:

```text
CML-AUDIT-R1-MISSING_PARENT
CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL
CML-AUDIT-RANGE-DRIFT
```

See [`docs/integrations/GROK_XAI_AGENT_INTEGRATION.md`](docs/integrations/GROK_XAI_AGENT_INTEGRATION.md)
for host-side xAI function-calling, LangGraph, CrewAI, custom ReAct,
prompt-engineering, Cause Band, and MCP integration patterns.

The example is not an official xAI integration or endorsement. It performs no
real network call, code execution, file mutation, or external send.
