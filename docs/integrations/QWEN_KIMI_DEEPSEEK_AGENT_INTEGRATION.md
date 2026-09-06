# Qwen, Kimi, and DeepSeek Agent Integration

## Status and scope

This guide maps current OpenAI-compatible tool-calling flows for Qwen, Kimi,
and DeepSeek into Causal Memory Layer (CML) records.

Run the deterministic example:

```bash
python examples/qwen_kimi_deepseek_causal_audit.py
```

The example performs no provider requests, tool execution, file mutation, or
network access. It is not an official endorsement or partnership with Alibaba,
Moonshot AI, or DeepSeek.

CML remains a read-only causal-validity layer. The host application decides
whether a failed audit should block, defer, or request human approval.

## Shared transport pattern

The verified paths in this guide use OpenAI-compatible Chat Completions tool
calling:

```text
assistant.tool_calls[*].id
        ↓
role="tool", tool_call_id=<same id>
```

This ID correlates a tool result with a tool request. It does not prove why the
action was authorized.

CML keeps a separate causal layer:

```text
tool_call_id  -> which tool output belongs to which API request?
parent_cause  -> which task, evidence, delegation, or approval caused it?
permitted_by  -> which semantic permission allowed it?
```

## Provider matrix

| Provider | Verified API path | Request field | Result correlation | Important nuance |
| --- | --- | --- | --- | --- |
| Qwen | Alibaba Cloud Model Studio OpenAI-compatible Chat Completions | `assistant.tool_calls` | `role="tool"` + `tool_call_id` | Disable or explicitly manage thinking when a deterministic pre-tool gate is required. |
| Kimi | Kimi models deployed through Alibaba Cloud Model Studio | `assistant.tool_calls` | `role="tool"` + `tool_call_id` | In thinking mode, preserve `reasoning_content` in assistant history; do not store raw reasoning in CML. |
| DeepSeek | DeepSeek Chat Completions API | `assistant.tool_calls` | `role="tool"` + `tool_call_id` | The host executes the function; strict schema mode is a beta API feature. |

Official references:

- [Alibaba Cloud Model Studio Function Calling](https://help.aliyun.com/zh/model-studio/qwen-function-calling)
- [DeepSeek Function Calling](https://api-docs.deepseek.com/guides/function_calling)

The Kimi behavior documented here is the currently verified Model Studio path.
It should not be presented as a claim about every Moonshot-hosted endpoint.

## CML record shape

Provider metadata stays inside the existing JSON-compatible `object` payload:

```python
CausalRecord(
    id="tool-call-42",
    timestamp=42,
    actor=agent_actor,
    action="send",
    object={
        "tool": "send_report",
        "intent_description": "Send the approved report.",
        "risk_level": "high",
        "human_approval": {
            "required": True,
            "status": "approved:ticket-42",
        },
        "evidence_bundle": {
            "request_digest": "sha256:...",
            "result_digest": "sha256:...",
        },
        "provider_envelope": {
            "provider": "qwen",
            "assistant_message": {
                "role": "assistant",
                "finish_reason": "tool_calls",
                "tool_call": {
                    "type": "function",
                    "id": "call_123",
                    "function": {
                        "name": "send_report",
                        "arguments_digest": "sha256:..."
                    }
                }
            },
            "tool_message": {
                "role": "tool",
                "tool_call_id": "call_123",
                "content_digest": "sha256:..."
            }
        }
    },
    permitted_by="human_approval:ticket-42",
    parent_cause="approval-42",
)
```

The stable CML schema is unchanged.

## Qwen

Alibaba Cloud Model Studio documents the standard multi-step flow:

1. Send user messages and tool declarations.
2. Receive `assistant.tool_calls` with function name, arguments, and a unique
   tool-call ID.
3. Execute the tool in the application.
4. Append the assistant message.
5. Append a `role="tool"` message using the same `tool_call_id`.
6. Call the model again for the final response.

A simplified host-side adapter:

```python
from openai import OpenAI

client = OpenAI(
    api_key=DASHSCOPE_API_KEY,
    base_url=MODEL_STUDIO_COMPATIBLE_URL,
)

response = client.chat.completions.create(
    model=QWEN_MODEL,
    messages=messages,
    tools=TOOLS,
    extra_body={"enable_thinking": False},
)

assistant = response.choices[0].message
messages.append(assistant)

for call in assistant.tool_calls or []:
    proposed = make_cml_proposal(
        provider_call_id=call.id,
        tool_name=call.function.name,
        arguments_json=call.function.arguments,
        parent_cause=current_cause_id,
    )

    audit = audit_proposed_trace([*records, proposed])
    if audit.passed():
        raw_result = execute_host_tool(call.function.name, call.function.arguments)
        observed = attach_result_evidence(proposed, raw_result)
        records.append(observed)
        current_cause_id = observed.id
    else:
        raw_result = {
            "status": "causal_review_required",
            "findings": audit.to_dict(),
        }

    messages.append(
        {
            "role": "tool",
            "tool_call_id": call.id,
            "content": serialize(raw_result),
        }
    )
```

For thinking-capable Qwen models, provider history may include
`reasoning_content`. CML should not treat that content as causal proof or store
raw private reasoning. Use observed tool requests, results, approvals, and
stable record IDs as evidence.

## Kimi

Alibaba Cloud currently documents Kimi deployments that use the same
OpenAI-compatible `tool_calls` / `tool_call_id` flow.

For the listed thinking-mode Kimi models, every assistant message must preserve
its `reasoning_content` field in the provider conversation history, and the
supported `tool_choice` values are currently `auto` and `none`.

Recommended handling:

```text
provider conversation buffer:
  preserve reasoning_content exactly when required by the provider

CML audit record:
  stored_raw_in_cml = false
  replayed_to_provider = true
  digest = sha256(...)
```

This distinction matters:

- provider replay requirements are transport state;
- raw reasoning is not authorization evidence;
- CML `intent_description` should remain a concise action-level purpose;
- human approval must originate from a trusted host or explicit human action.

A model must never mint its own approval ID.

## DeepSeek

DeepSeek's official function-calling guide uses the OpenAI Python client with a
DeepSeek base URL. The response contains `message.tool_calls`; the host executes
the function and appends:

```python
{
    "role": "tool",
    "tool_call_id": tool.id,
    "content": serialized_result,
}
```

DeepSeek explicitly notes that the model does not execute the function itself.
That host boundary is the correct place for a CML pre-tool gate.

```python
message = client.chat.completions.create(
    model="deepseek-chat",
    messages=messages,
    tools=TOOLS,
).choices[0].message

messages.append(message)

for tool in message.tool_calls or []:
    proposed = make_cml_proposal(
        provider_call_id=tool.id,
        tool_name=tool.function.name,
        arguments_json=tool.function.arguments,
        parent_cause=current_cause_id,
    )

    audit = audit_proposed_trace([*records, proposed])
    result = (
        execute_host_tool(tool.function.name, tool.function.arguments)
        if audit.passed()
        else {"status": "causal_review_required"}
    )

    messages.append(
        {
            "role": "tool",
            "tool_call_id": tool.id,
            "content": serialize(result),
        }
    )
```

DeepSeek also documents a beta `strict` mode for schema-conforming function
arguments. Schema conformance improves argument shape; it does not prove human
approval, intent continuity, or valid causal lineage.

## Parallel tool calls

If a provider requests several tools in one assistant message, keep one CML
branch per call:

```text
root task
  ├─ call A -> record A
  ├─ call B -> record B
  └─ call C -> record C
                    ↓
          explicit synthesis/join record
```

Do not use completion order as a substitute for causal structure.

## Human approval rule

```yaml
custom_rules:
  - id: R8_DATA_EGRESS_REQUIRES_HUMAN_APPROVAL
    description: High-risk external data egress requires human approval.
    trigger_class: DATA_EGRESS
    severity: FAIL
    code: CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL
    require_ancestor_class: OVERRIDE
    require_ancestor_permitted_by_prefix: "human_approval:"
```

`tool_call_id` proves correlation, not approval.

## Prompt metadata

Ask for reviewable action claims, not private chain-of-thought:

```text
Before requesting a tool, provide:
- one sentence describing the action intent;
- the parent CML record ID supplied by the host;
- a low, medium, or high risk level;
- whether human approval is required;
- evidence record IDs used for the action.

Do not invent parent IDs or approval IDs.
```

The host should independently capture tool arguments, provider IDs, timestamps,
results, identities, evidence digests, and approval state.

## Cause Band

Cause Band is an experimental future direction for multi-step intent-drift
tracking. Its findings are non-normative and do not represent a production
safety guarantee.

## Run and validate

```bash
python examples/qwen_kimi_deepseek_causal_audit.py
pytest tests/test_qwen_kimi_deepseek_causal_audit_demo.py
```

Invalid traces should report missing-parent and missing-human-approval findings.
Valid traces should pass the core CML audit.
