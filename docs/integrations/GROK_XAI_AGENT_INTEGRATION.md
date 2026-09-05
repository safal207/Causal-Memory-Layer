# Grok / xAI-Style LLM Agent Integration

## Status and scope

This guide describes how to map modern LLM tool-use traces into Causal Memory
Layer (CML) records and audit them for causal lineage, approval ancestry, and
experimental Cause Band drift.

The accompanying demo is SDK-independent:

```bash
python examples/grok_xai_causal_audit.py
```

It simulates a Grok/xAI-style tool loop without calling xAI, executing code,
writing files, or sending network requests.

This is **not** an official xAI integration or endorsement. CML remains a
read-only audit primitive. It does not automatically block tools, certify
safety, or expose a production hosted MCP endpoint.

## Why causal audit matters for LLM agents

A tool-calling agent can be operationally successful while losing the reason
that authorized the action.

For example:

```text
user request
  -> web search
  -> sandbox calculation
  -> local report
  -> external send
```

The final send may return HTTP 202 and still be causally invalid when:

- the root request only authorized local analysis;
- the external action points to a missing approval record;
- the task intent drifted across several reasoning/tool steps;
- the evidence used to justify the action is absent or cannot be replayed;
- the model effectively approved its own high-risk action.

CML makes those review questions explicit in structured records.

## LLM-native record mapping

The stable vCML record schema already provides the key lineage fields:

```python
CausalRecord(
    id="tool-call-42",
    timestamp=42,
    actor=agent_actor,
    action="send",
    object={...},
    permitted_by="human_approval:ticket-42",
    parent_cause="approval-42",
)
```

Agent-specific metadata should currently be stored inside the JSON-compatible
`object` payload rather than added as new top-level fields:

```json
{
  "tool": "external_api_call",
  "intent_description": "Send the approved report to the named endpoint.",
  "risk_level": "high",
  "human_approval": {
    "required": true,
    "status": "approved:ticket-42"
  },
  "request": {
    "endpoint": "https://example.invalid/reports",
    "method": "POST"
  },
  "result": {
    "status": "simulated_success",
    "http_status": 202
  },
  "evidence_bundle": {
    "request_digest": "sha256:...",
    "result_digest": "sha256:...",
    "artifacts": ["workspace/report.md"],
    "simulated": true
  }
}
```

Recommended minimum fields for each tool call:

| Field | Purpose |
| --- | --- |
| `parent_cause` | Links the call to the task, evidence, approval, or prior tool result that caused it. |
| `intent_description` | A short action-level purpose, not hidden chain-of-thought. |
| `risk_level` | Application-defined classification such as `low`, `medium`, or `high`. |
| `human_approval` | Whether approval is required and the observed approval status or ID. |
| `evidence_bundle` | Digests and artifact references needed to review or replay the action. |
| `permitted_by` | The semantic permission reference, such as `task:...`, `policy:...`, or `human_approval:...`. |

## Integration patterns

### 1. Pre-tool gate

Before executing a tool, build a proposed CML record and inspect its lineage.
The application—not CML—decides whether a failed audit should block execution.

```python
from cml.audit import AuditConfig, AuditEngine


def pre_tool_gate(records, proposed_record, rules_yaml: str) -> None:
    config = AuditConfig.from_yaml_string(rules_yaml)
    result = AuditEngine(config).run([*records, proposed_record])

    if not result.passed():
        codes = [finding.code for finding in result.findings]
        raise PermissionError(f"Tool call requires review: {codes}")
```

Use this pattern for irreversible or externally visible actions such as:

- sending messages;
- changing production data;
- financial transactions;
- publishing artifacts;
- executing privileged code;
- transferring sensitive data.

### 2. Post-action audit

For low-risk or read-only tools, record the observed result and audit after the
call. This gives developers a replayable trace even when the application does
not enforce a synchronous gate.

```python
result = tool_fn(**arguments)
record = make_cml_record(
    tool_name=tool_name,
    arguments=arguments,
    result=result,
    parent_cause_id=current_cause_id,
)
records.append(record)

audit_result = AuditEngine(config).run(records)
```

### 3. Long-term causal memory

Persist CML records as append-only JSONL or in a store that preserves record
IDs. A later agent session should reference prior evidence by record ID rather
than copying an untraceable natural-language summary.

Useful long-term questions include:

```text
Which approval authorized this external action?
Which evidence caused the agent to revise the plan?
Did a new session inherit an unresolved causal gap?
Did the action remain within the original intent range?
```

### 4. Hybrid pattern

A practical default is:

```text
read-only tool        -> execute -> record -> post-action audit
sandbox execution     -> lightweight policy check -> execute -> record
external/high-risk    -> explicit approval -> pre-tool gate -> execute -> record
```

## Grok / xAI function-calling loop

xAI function calling follows the common pattern: the model requests a custom
function, the application executes it, returns the tool result, and the model
continues. CML fits at the boundary where the application receives the tool
request.

The following adapter is intentionally simplified and uses placeholders for
application-specific tool execution:

```python
import json
import os

from openai import OpenAI

from cml.audit import AuditEngine

client = OpenAI(
    api_key=os.environ["XAI_API_KEY"],
    base_url="https://api.x.ai/v1",
)

response = client.responses.create(
    model=os.environ["XAI_MODEL"],
    input=[{"role": "user", "content": "Research this topic and save a local report."}],
    tools=TOOLS,
)

for item in response.output:
    if item.type != "function_call":
        continue

    arguments = json.loads(item.arguments)
    proposed_record = record_proposed_tool_call(
        call_id=item.call_id,
        tool_name=item.name,
        arguments=arguments,
        parent_cause_id=current_cause_id,
    )

    # The host application defines enforcement behavior.
    pre_result = AuditEngine(config).run([*records, proposed_record])
    if not pre_result.passed():
        tool_output = {"error": "causal_review_required", "audit": pre_result.to_dict()}
    else:
        raw_result = TOOLS_MAP[item.name](**arguments)
        observed_record = attach_result_evidence(proposed_record, raw_result)
        records.append(observed_record)
        current_cause_id = observed_record.id
        tool_output = raw_result

    response = client.responses.create(
        model=os.environ["XAI_MODEL"],
        previous_response_id=response.id,
        input=[{
            "type": "function_call_output",
            "call_id": item.call_id,
            "output": json.dumps(tool_output),
        }],
        tools=TOOLS,
    )
```

Important boundary: xAI built-in server-side tools may execute outside the
custom host callback. For complete causal coverage, ingest the returned tool
metadata and citations into CML records after the response, or route sensitive
operations through custom functions that the host can gate.

## Custom ReAct loop

A framework-free loop can keep the causal cursor beside the message history:

```python
records = [root_request_record]
current_cause_id = root_request_record.id

while True:
    decision = model_decide(messages, available_tools)

    if decision.kind == "final":
        break

    proposed = record_proposed_tool_call(
        call_id=decision.call_id,
        tool_name=decision.tool_name,
        arguments=decision.arguments,
        parent_cause_id=current_cause_id,
    )

    gate = AuditEngine(config).run([*records, proposed])
    if not gate.passed():
        messages.append({"role": "tool", "content": gate.to_dict()})
        continue

    result = execute_tool(decision.tool_name, decision.arguments)
    observed = attach_result_evidence(proposed, result)
    records.append(observed)
    current_cause_id = observed.id
    messages.append({"role": "tool", "content": result})
```

Do not use unrestricted model prose as the `parent_cause`. Parent causes should
be stable record IDs.

## LangGraph pattern

Store the CML trace and causal cursor in graph state. Wrap every tool node so it
reads the cursor and returns the new record ID.

```python
from typing import TypedDict


class AgentState(TypedDict):
    messages: list
    cml_records: list
    cml_parent_cause_id: str


def audited_tool_node(state: AgentState) -> AgentState:
    call = extract_tool_call(state["messages"])
    proposed = record_proposed_tool_call(
        call_id=call.id,
        tool_name=call.name,
        arguments=call.args,
        parent_cause_id=state["cml_parent_cause_id"],
    )

    gate = AuditEngine(config).run([*state["cml_records"], proposed])
    if not gate.passed():
        return add_audit_failure_message(state, gate.to_dict())

    output = TOOLS_MAP[call.name](**call.args)
    observed = attach_result_evidence(proposed, output)

    return {
        **state,
        "messages": append_tool_result(state["messages"], call.id, output),
        "cml_records": [*state["cml_records"], observed],
        "cml_parent_cause_id": observed.id,
    }
```

For parallel branches, keep one parent cursor per branch and create an explicit
join record when results are merged. Do not silently choose the last completed
branch as the only cause.

## CrewAI pattern

CML can wrap a CrewAI tool boundary without requiring changes to the model.
The repository also contains a CrewAI-style trace example:

```text
examples/crewai_style_causal_audit.py
```

A minimal wrapper shape:

```python
def audited_crewai_tool(tool_name, tool_fn, *, risk_level):
    def run(**arguments):
        proposed = record_proposed_tool_call(
            call_id=new_call_id(),
            tool_name=tool_name,
            arguments=arguments,
            parent_cause_id=crew_context.current_cause_id,
            risk_level=risk_level,
        )

        gate = AuditEngine(config).run([*crew_context.records, proposed])
        if not gate.passed():
            return {"error": "causal_review_required", "audit": gate.to_dict()}

        result = tool_fn(**arguments)
        observed = attach_result_evidence(proposed, result)
        crew_context.records.append(observed)
        crew_context.current_cause_id = observed.id
        return result

    return run
```

For delegated tasks, add an explicit delegation record so the child agent's
first tool call descends from the parent agent's assignment.

## Prompt engineering with CML

Ask the model for concise, reviewable metadata—not private chain-of-thought.

Suggested system/developer instruction:

```text
Before requesting a tool, provide structured metadata containing:
- a one-sentence action intent;
- the parent cause record ID supplied by the host;
- a risk level from low, medium, or high;
- whether human approval is required;
- the evidence record IDs used for the decision.

Never claim that human approval exists unless the host supplies a valid
approval record ID. Do not invent parent cause IDs. Keep private reasoning out
of the audit metadata.
```

Host-side validation should reject:

- unknown parent IDs;
- model-created approval IDs;
- risk levels outside the configured enum;
- evidence digests that do not match captured payloads;
- tool calls whose declared intent conflicts with the actual arguments;
- sensitive actions that rely only on model-generated justification.

The model's metadata is an audit claim, not proof. The host should derive as
much evidence as possible from observed tool requests, results, identities, and
approval systems.

## Cause Band tracking

Cause Band is experimental and opt-in. It tracks whether the action trajectory
remains inside the intended causal range across multiple steps.

Example sidecar:

```json
{
  "case_id": "agent-intent-drift",
  "status": "experimental",
  "cause_band_policy": {
    "duration_threshold": "2_steps"
  },
  "trajectory": [
    {"step": 1, "band": "safe_range"},
    {"step": 2, "band": "warning_range"},
    {"step": 3, "band": "danger_range"},
    {"step": 4, "band": "critical_range"}
  ]
}
```

Evaluate it from Python:

```python
from cml.experimental.cause_band import evaluate_fixture

result = evaluate_fixture(sidecar)
print(result["predicted_codes"])
```

Possible experimental findings include:

```text
CML-AUDIT-RANGE-DRIFT
CML-AUDIT-RANGE-PERSISTENT_DEVIATION
CML-AUDIT-RANGE-CRITICAL_EXIT
```

Cause Band findings are non-normative and should not be described as stable
production safety guarantees.

## MCP integration

### Local MCP-compatible clients

Install and run the current local CML MCP server:

```bash
pip install "causal-memory-layer[mcp]"
cml-mcp
```

Current tools:

```text
health
audit_trace
evaluate_cause_band
```

See:

```text
docs/integrations/MCP_AGENT_AUDIT.md
```

### xAI Remote MCP

xAI Remote MCP expects a reachable MCP server using a supported remote
transport. The current repository only documents the local `cml-mcp` process
and does not claim a hosted endpoint.

A future hosted adapter could be configured conceptually as:

```python
response = client.responses.create(
    model=os.environ["XAI_MODEL"],
    input="Audit this agent trace before the external action.",
    tools=[{
        "type": "mcp",
        "server_url": "https://your-authenticated-cml-host.example/mcp",
        "server_label": "cml_audit",
        "allowed_tools": ["audit_trace", "evaluate_cause_band"],
        "authorization": os.environ["CML_MCP_AUTHORIZATION"],
    }],
)
```

Before publishing a remote endpoint, add:

- authenticated transport;
- strict payload size limits;
- rate limiting;
- tenant isolation;
- request and response redaction;
- allow-listed CML tools;
- replay protection and signed evidence receipts;
- deployment and threat-model documentation.

## Interpreting audit findings

### `CML-AUDIT-R1-MISSING_PARENT`

A record references a parent cause that is absent from the trace.

Typical agent meaning:

```text
The tool call claims an approval/task/evidence parent that the reviewer cannot
find or verify.
```

### `CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL`

This demo-defined custom rule requires a high-risk `DATA_EGRESS` action to have
an ancestor whose CTAG class is `OVERRIDE` and whose permission starts with
`human_approval:`.

Typical agent meaning:

```text
The external action may be structurally connected to prior reasoning, but no
valid human approval record exists in its ancestry.
```

### Cause Band drift

A trajectory moved outside the configured safe range. Review whether the tool
sequence changed the task's purpose, scope, recipient, data sensitivity, or
irreversibility.

## Roadmap for xAI / Grok tool-use

### Phase 1 — repository-native demo

- Keep the demo SDK-independent and deterministic.
- Add regression tests for valid and invalid tool-use traces.
- Publish a reviewer-friendly expected-output snapshot.

### Phase 2 — host-side xAI adapter

- Map Responses API function-call IDs to CML record IDs.
- Capture custom function arguments and outputs as evidence digests.
- Add post-action ingestion for xAI built-in tool metadata and citations.
- Define an application risk taxonomy for each exposed tool.

### Phase 3 — remote MCP transport

- Add an authenticated Streaming HTTP/SSE deployment path.
- Restrict xAI access to `audit_trace` and `evaluate_cause_band` initially.
- Add deployment fixtures and an end-to-end remote integration test.

### Phase 4 — stronger evidence

- Replace placeholder integrity fields with signed receipts.
- Bind approval identities, tool-call IDs, payload digests, and timestamps.
- Add tamper-evident replay and third-party verification tests.

### Phase 5 — evaluation and collaboration

- Benchmark missing approvals, forged parents, tool substitution, parallel
  branch joins, delayed external actions, and multi-session intent drift.
- Publish non-claims beside every benchmark result.
- Pursue framework and provider collaboration only after reproducible local
  evidence exists.

## Run the demo

```bash
pip install -e ".[dev]"
python examples/grok_xai_causal_audit.py
pytest tests/test_grok_xai_causal_audit_demo.py
```

Expected high-level output:

```text
Invalid trace: REVIEW REQUIRED
- CML-AUDIT-R1-MISSING_PARENT
- CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL
- Cause Band drift findings

Valid trace: VALID CAUSAL CHAIN
- no core findings
- intent remains in safe_range
```

## Related repository material

- `examples/crewai_style_causal_audit.py`
- `examples/agent_approval_lineage_audit.py`
- `docs/integrations/CREWAI_STYLE_CAUSAL_AUDIT.md`
- `docs/integrations/MCP_AGENT_AUDIT.md`
- `docs/research/CAUSE_BAND.md`
- `docs/demo/AGENT_INTENT_DRIFT_CAUSE_BAND_EXAMPLE.md`
- `docs/NON_CLAIMS.md`
