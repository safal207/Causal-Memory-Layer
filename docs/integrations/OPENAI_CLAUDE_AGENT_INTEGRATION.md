# OpenAI and Claude Agent Integration

## Status and scope

This guide maps OpenAI Responses API and Claude Messages API tool-use events
into Causal Memory Layer (CML) records.

The accompanying demo is deterministic and SDK-independent:

```bash
python examples/openai_claude_causal_audit.py
```

It does not call OpenAI or Anthropic, execute tools, write files, or send network
requests. It is not an official integration or endorsement by either provider.

CML remains a read-only causal-validity layer. It records and audits why an
action was permitted; the host application decides whether to continue, defer,
request approval, or block execution.

## Shared CML record

Provider-specific correlation data belongs inside the JSON-compatible `object`
payload while the stable CML fields keep their existing meaning:

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
        "provider_envelope": {...},
    },
    permitted_by="human_approval:ticket-42",
    parent_cause="approval-42",
)
```

The provider envelope is useful for transport correlation. It does not replace
`parent_cause`, `permitted_by`, evidence digests, or approval ancestry.

## OpenAI Responses API

OpenAI custom function calling returns response output items with:

- `type: "function_call"`;
- a `call_id`;
- a function `name`;
- JSON-encoded `arguments`.

The host executes the function and sends a `function_call_output` item with the
same `call_id`.

Official references:

- [Function calling](https://developers.openai.com/api/docs/guides/function-calling)
- [Using tools](https://developers.openai.com/api/docs/guides/tools)

### CML mapping

```json
{
  "provider": "openai",
  "api": "responses",
  "execution_boundary": "host_custom_function",
  "request_item": {
    "type": "function_call",
    "call_id": "call_123",
    "name": "send_report",
    "arguments_digest": "sha256:..."
  },
  "result_item": {
    "type": "function_call_output",
    "call_id": "call_123",
    "output_digest": "sha256:..."
  }
}
```

Use the provider `call_id` for API correlation and a CML record ID for causal
lineage. They answer different questions:

```text
call_id       -> which OpenAI function output belongs to this function call?
parent_cause  -> which task, evidence, delegation, or approval caused it?
```

### Host-side adapter shape

```python
import json
import os

from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

response = client.responses.create(
    model=os.environ["OPENAI_MODEL"],
    input="Prepare a report and send it only after approval.",
    tools=TOOLS,
)

for item in response.output:
    if item.type != "function_call":
        continue

    arguments = json.loads(item.arguments)
    proposed = make_cml_proposal(
        provider_call_id=item.call_id,
        tool_name=item.name,
        arguments=arguments,
        parent_cause=current_cause_id,
    )

    audit = audit_proposed_trace([*records, proposed])
    if not audit.passed():
        output = {
            "status": "causal_review_required",
            "findings": audit.to_dict(),
        }
    else:
        raw_result = execute_host_tool(item.name, arguments)
        observed = attach_result_evidence(proposed, raw_result)
        records.append(observed)
        current_cause_id = observed.id
        output = raw_result

    next_input.append(
        {
            "type": "function_call_output",
            "call_id": item.call_id,
            "output": json.dumps(output),
        }
    )
```

Use strict function schemas where possible. Schema conformance improves argument
shape, but it does not prove that the action has valid causal authorization.

### Built-in OpenAI tools

The Responses API also supports built-in tools such as web search, file search,
remote MCP, shell, and code execution. Some operations occur outside a custom
host function callback.

For those tools:

1. ingest returned tool events, citations, artifact IDs, and outputs;
2. create observed CML records after the response;
3. connect each record to the task or prior evidence through `parent_cause`;
4. route externally visible or irreversible actions through host-controlled
   functions when explicit approval must be checked before execution.

## Claude Messages API

For client-side tools, Claude responds with:

- `stop_reason: "tool_use"`;
- one or more `tool_use` content blocks;
- an `id`, tool `name`, and structured `input`.

The host executes the tool and sends a `tool_result` block whose
`tool_use_id` references the original tool-use block.

Official references:

- [Tool use with Claude](https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview)
- [MCP connector](https://platform.claude.com/docs/en/agents-and-tools/mcp-connector)

### CML mapping

```json
{
  "provider": "claude",
  "api": "messages",
  "execution_boundary": "client_side_tool",
  "assistant_stop_reason": "tool_use",
  "request_block": {
    "type": "tool_use",
    "id": "toolu_123",
    "name": "send_report",
    "input_digest": "sha256:..."
  },
  "result_block": {
    "type": "tool_result",
    "tool_use_id": "toolu_123",
    "is_error": false,
    "content_digest": "sha256:..."
  }
}
```

As with OpenAI, `tool_use_id` correlates transport blocks while
`parent_cause` preserves authorization and responsibility lineage.

### Host-side adapter shape

```python
import os

from anthropic import Anthropic

client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

message = client.messages.create(
    model=os.environ["ANTHROPIC_MODEL"],
    max_tokens=2048,
    messages=messages,
    tools=TOOLS,
)

if message.stop_reason == "tool_use":
    tool_results = []

    for block in message.content:
        if block.type != "tool_use":
            continue

        proposed = make_cml_proposal(
            provider_call_id=block.id,
            tool_name=block.name,
            arguments=block.input,
            parent_cause=current_cause_id,
        )

        audit = audit_proposed_trace([*records, proposed])
        if not audit.passed():
            result_content = {
                "status": "causal_review_required",
                "findings": audit.to_dict(),
            }
            is_error = True
        else:
            raw_result = execute_host_tool(block.name, block.input)
            observed = attach_result_evidence(proposed, raw_result)
            records.append(observed)
            current_cause_id = observed.id
            result_content = raw_result
            is_error = False

        tool_results.append(
            {
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": serialize(result_content),
                "is_error": is_error,
            }
        )
```

Claude server-side tools execute on Anthropic infrastructure. For those tools,
record the returned events and results after execution. Use client-side tools
for operations that require a host-side approval check before execution.

## Claude MCP connector

The current Claude Messages API MCP connector separates:

- remote server connection details in `mcp_servers`;
- enabled tool configuration in `tools` using an `mcp_toolset`.

CML's current MCP implementation is a local FastMCP developer integration, not
a hosted authenticated remote endpoint. A future remote deployment would need:

- HTTPS transport;
- authentication and tenant isolation;
- explicit tool allowlists;
- request and result evidence capture;
- stable causal record IDs;
- operational security review.

Do not present the existing local CML MCP server as directly compatible with a
remote provider connector until that transport and authentication layer exists.

## Approval rule

A provider-neutral high-risk rule can require a human approval ancestor:

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

The model must not create its own approval record. Approval IDs should originate
from a trusted host system or an explicit human action.

## Prompt metadata

Ask models for concise audit claims, not private chain-of-thought:

```text
Before requesting a tool, provide:
- one sentence describing the action intent;
- the parent CML record ID supplied by the host;
- a low, medium, or high risk level;
- whether human approval is required;
- evidence record IDs used by the action.

Do not invent parent IDs or approval IDs.
```

Model-provided metadata is an audit claim. The host should independently derive
tool arguments, identities, timestamps, results, and approval state wherever
possible.

## Cause Band

Cause Band is an experimental future direction for multi-step intent-drift
tracking. Its findings are non-normative and do not represent a production
safety guarantee.

## Run and validate

```bash
python examples/openai_claude_causal_audit.py
pytest tests/test_openai_claude_causal_audit_demo.py
```

The invalid provider traces should report:

- `CML-AUDIT-R1-MISSING_PARENT`;
- `CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL`;
- experimental Cause Band drift findings.

The valid provider traces should pass the core CML audit.
