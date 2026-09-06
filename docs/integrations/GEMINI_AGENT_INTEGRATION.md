# Gemini Agent Integration

## Status and scope

This guide maps Gemini API custom function calling into Causal Memory Layer
(CML) records.

Run the deterministic, SDK-independent example:

```bash
python examples/gemini_causal_audit.py
```

The example does not call Gemini, execute tools, write files, or send network
requests. It is not an official Google integration or endorsement.

CML remains a read-only causal-validity layer. The host application decides
whether an audit finding should block, defer, or request human approval.

## Why Gemini needs a causal layer

Gemini transport metadata can correlate a function result with the function
call that requested it. CML answers a different question:

```text
Gemini function id -> which functionResponse belongs to this functionCall?
CML parent_cause   -> which task, evidence, delegation, or approval caused it?
```

A technically correct `functionResponse` can still represent a causally invalid
action if its approval or responsibility lineage is missing.

## Current Gemini function-calling flow

For custom tools:

1. The application declares functions.
2. Gemini returns a structured `functionCall` with a function name, arguments,
   and a unique `id` for Gemini 3 models.
3. The host application executes the function.
4. The host returns a `functionResponse` with the exact matching `id`.
5. Gemini continues with a final answer or another tool call.

Official references:

- [Gemini API function calling](https://ai.google.dev/gemini-api/docs/function-calling)
- [Using tools with Gemini](https://ai.google.dev/gemini-api/docs/tools)
- [Vertex AI function calling](https://cloud.google.com/vertex-ai/generative-ai/docs/multimodal/function-calling)

The Python SDK exposes snake_case fields such as `function_call` and
`function_response`; the wire format uses `functionCall` and
`functionResponse`.

## CML record mapping

Provider-specific metadata stays inside the JSON-compatible `object` payload:

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
            "provider": "gemini",
            "api": "generateContent",
            "execution_boundary": "host_custom_function",
            "model_part": {
                "wire_key": "functionCall",
                "id": "gemini-function-id",
                "name": "send_report",
                "args_digest": "sha256:..."
            },
            "user_part": {
                "wire_key": "functionResponse",
                "id": "gemini-function-id",
                "name": "send_report",
                "response_digest": "sha256:..."
            }
        }
    },
    permitted_by="human_approval:ticket-42",
    parent_cause="approval-42",
)
```

The stable CML schema is unchanged.

## Manual host-side gate

For high-risk actions, keep the function execution boundary visible to the
host. A simplified Google GenAI SDK shape:

```python
import os

from google import genai
from google.genai import types

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

config = types.GenerateContentConfig(
    tools=[types.Tool(function_declarations=FUNCTION_DECLARATIONS)],
    automatic_function_calling=types.AutomaticFunctionCallingConfig(
        disable=True
    ),
)

response = client.models.generate_content(
    model=os.environ["GEMINI_MODEL"],
    contents="Prepare a report and send it only after approval.",
    config=config,
)

model_content = response.candidates[0].content
function_responses = []

for part in model_content.parts:
    if not part.function_call:
        continue

    call = part.function_call
    proposed = make_cml_proposal(
        provider_call_id=call.id,
        tool_name=call.name,
        arguments=dict(call.args),
        parent_cause=current_cause_id,
    )

    audit = audit_proposed_trace([*records, proposed])
    if not audit.passed():
        raw_result = {
            "status": "causal_review_required",
            "findings": audit.to_dict(),
        }
    else:
        raw_result = execute_host_tool(call.name, dict(call.args))
        observed = attach_result_evidence(proposed, raw_result)
        records.append(observed)
        current_cause_id = observed.id

    function_responses.append(
        types.Part.from_function_response(
            name=call.name,
            response=raw_result,
            # Use the SDK/API field that preserves the exact call ID.
            id=call.id,
        )
    )

history = [
    original_user_content,
    model_content,
    types.Content(role="user", parts=function_responses),
]
```

The exact SDK constructor may evolve; the invariant is stable: return the exact
function-call `id` with its response.

## Automatic function calling

The Google GenAI Python SDK can automatically:

1. detect requested function calls;
2. execute supplied Python functions;
3. return function responses to Gemini;
4. produce the final text response.

That is convenient for low-risk tools. For a pre-execution CML gate, automatic
execution can hide the moment where the host should validate approval lineage.
Recommended choices:

- disable automatic function calling for irreversible or externally visible
  tools;
- wrap the supplied Python function with a CML gate before its real body;
- use post-action audit only for read-only or low-risk operations.

## Thought signatures

Gemini 3 response parts may include opaque `thought_signature` values. When
conversation history is manually managed, Google requires those signatures to
be returned in their original parts, and function calling requires signature
preservation.

CML guidance:

- preserve the original signed response part in the provider conversation
  buffer;
- do not parse or reinterpret the signature as model reasoning;
- do not copy raw signatures into public audit logs;
- optionally record a digest, presence flag, and preservation status in CML;
- keep private chain-of-thought out of `intent_description`.

The demo uses:

```json
{
  "thought_signature": {
    "present": true,
    "preserved_opaque": true,
    "stored_raw": false,
    "digest": "sha256:..."
  }
}
```

This records handling state, not hidden reasoning content.

## Parallel function calls

Gemini can request multiple independent functions in one turn. For Gemini 3,
results can be correlated through unique function IDs, including when results
complete out of order.

CML should not collapse parallel calls into one implicit cause:

```text
root task
  ├─ functionCall A -> CML record A
  └─ functionCall B -> CML record B
                         ↓
               explicit causal join record
```

Each branch gets its own `parent_cause`. If later reasoning combines both
results, create an explicit join or synthesis record referencing the branch
outputs according to the application's causal model.

## Compositional function calling

For sequential calls, advance the causal cursor only after the prior result has
been observed and recorded:

```text
user request
  -> get_current_location
  -> get_weather(location)
  -> set_thermostat(weather)
```

The Gemini function ID correlates each API pair. The CML chain captures why the
next action followed from the prior result.

## Built-in Gemini tools

Gemini built-in tools such as Google Search, Google Maps, URL Context, File
Search, and Code Execution are managed by Google and may execute within one API
call. The host does not receive the same pre-execution callback as a custom
function.

For built-in tools:

1. ingest returned grounding metadata, tool events, citations, artifacts, and
   outputs after the response;
2. create observed CML records for replay and review;
3. connect them to the root task or prior evidence through `parent_cause`;
4. route sensitive external actions through custom host functions when a CML
   pre-tool gate is required.

Computer Use is client-side and should be wrapped at the action-execution
boundary before clicks, typing, navigation, downloads, or submissions occur.

## Combined built-in and custom tools

Gemini 3 can combine built-in tools and custom function calls using tool-context
circulation. This capability may be preview depending on the model and API.
When manually continuing such a turn:

- preserve all original response parts and opaque signatures;
- return each matching function response ID;
- record built-in observations separately from host-executed actions;
- do not treat provider context circulation as human approval.

## Human approval rule

A provider-neutral rule can require a human approval ancestor for external data
egress:

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

The model must not mint its own approval record. Approval IDs should originate
from a trusted host system or explicit human action.

## Prompt metadata

Ask for concise audit claims, not private reasoning:

```text
Before requesting a custom function, provide:
- one sentence describing the action intent;
- the parent CML record ID supplied by the host;
- a low, medium, or high risk level;
- whether human approval is required;
- evidence record IDs used for the action.

Do not invent parent IDs or approval IDs.
```

The host should independently capture arguments, function IDs, timestamps,
results, identities, and approval state.

## Cause Band

Cause Band is an experimental future direction for tracking multi-step intent
drift. Its findings are non-normative and do not represent a production safety
guarantee.

## Run and validate

```bash
python examples/gemini_causal_audit.py
pytest tests/test_gemini_causal_audit_demo.py
```

The invalid trace should report:

- `CML-AUDIT-R1-MISSING_PARENT`;
- `CML-AUDIT-HIGH_RISK_WITHOUT_APPROVAL`;
- experimental Cause Band drift findings.

The valid trace should pass the core CML audit.
