# LLM Provider Causal-Audit Matrix

CML keeps one provider-neutral causal model while preserving each API's native
tool-call correlation metadata inside `CausalRecord.object`.

| Provider | Tool request | Tool result | Transport correlation | CML example | Integration guide |
| --- | --- | --- | --- | --- | --- |
| OpenAI Responses API | `function_call` | `function_call_output` | `call_id` | `examples/openai_claude_causal_audit.py` | `docs/integrations/OPENAI_CLAUDE_AGENT_INTEGRATION.md` |
| Claude Messages API | `tool_use` | `tool_result` | `tool_use_id` | `examples/openai_claude_causal_audit.py` | `docs/integrations/OPENAI_CLAUDE_AGENT_INTEGRATION.md` |
| Gemini generateContent | `functionCall` | `functionResponse` | function-call `id` | `examples/gemini_causal_audit.py` | `docs/integrations/GEMINI_AGENT_INTEGRATION.md` |
| Grok / xAI-style loop | `function_call` | host tool output | provider call ID | `examples/grok_xai_causal_audit.py` | `docs/integrations/GROK_XAI_AGENT_INTEGRATION.md` |

## The invariant

Provider IDs answer transport questions:

```text
Which result belongs to which requested tool call?
```

CML fields answer causal questions:

```text
Which task, evidence, delegation, policy, or human approval caused this action?
```

Recommended separation:

| Concern | Field |
| --- | --- |
| Provider message correlation | `object.provider_envelope` |
| Causal parent | `parent_cause` |
| Semantic permission | `permitted_by` |
| Human approval | `object.human_approval` plus an approval ancestor record |
| Evidence integrity | `object.evidence_bundle` |
| Action-level purpose | `object.intent_description` |
| Application risk class | `object.risk_level` |

A matching `call_id`, `tool_use_id`, or Gemini function `id` proves only that an
API result was correlated with its request. It does not prove authorization,
responsibility continuity, or human approval.

## Execution boundaries

| Boundary | Recommended CML pattern |
| --- | --- |
| Host-managed custom function | Pre-tool gate for high-risk actions, then observed result record |
| Read-only custom function | Execute, record, and run post-action audit |
| Provider-managed built-in tool | Ingest returned events and evidence after execution |
| Automatic function execution | Wrap the function body or disable automation where pre-tool approval is required |
| Parallel tool calls | One causal cursor per branch plus an explicit join record |
| Sequential tool calls | Advance the causal cursor after each observed result |

## Non-claims

These examples do not constitute official provider integrations or
endorsements. They perform no real model requests or tool execution. CML is a
read-only causal-validity primitive; host applications choose enforcement
behavior.

Cause Band remains experimental and non-normative. It does not represent a
production safety guarantee.
