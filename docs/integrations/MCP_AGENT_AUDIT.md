# CML Agent Audit MCP

## Status

This is an experimental integration skeleton.

It exposes CML audit functions as MCP tools so compatible AI clients can call CML as an external agent-audit layer.

It does not change stable CML semantics and does not provide enforcement, blocking, compliance certification, or production safety guarantees.

## Quickstarts

For a short local coding-assistant setup path, see:

```text
docs/integrations/CURSOR_MCP_QUICKSTART.md
```

## Why MCP?

CML is most useful when an AI-agent builder can ask:

```text
Audit this trace.
Was the action causally valid?
Did the reason drift over time?
```

The MCP integration turns CML into a tool server for compatible clients.

## Install

From the repository root:

```bash
pip install -e ".[mcp]"
```

For development:

```bash
pip install -e ".[dev,mcp]"
```

## Run

```bash
cml-mcp
```

Equivalent module form:

```bash
python -m cml.integrations.mcp.server
```

## Tools

Current tools:

```text
health
```

Returns integration status and available tools.

```text
audit_trace
```

Runs the core CML audit engine over JSON-compatible CML records.

Accepted payload shape:

```json
{
  "records": [
    {
      "id": "root",
      "timestamp": 1,
      "actor": {"pid": 100, "uid": 1000},
      "action": "exec",
      "object": "/bin/app",
      "permitted_by": "root_event:user_request",
      "parent_cause": null
    }
  ]
}
```

It also accepts a top-level list of records.

```text
evaluate_cause_band
```

Evaluates either a top-level experimental Cause Band fixture or an object containing `cause_band_sidecar`.

Accepted sidecar payload shape:

```json
{
  "cause_band_sidecar": {
    "case_id": "agent-intent-drift-sidecar-experimental",
    "status": "experimental",
    "cause_band_policy": {
      "duration_threshold": "3_steps"
    },
    "trajectory": [
      {"step": 1, "band": "safe_range"},
      {"step": 2, "band": "warning_range"},
      {"step": 3, "band": "danger_range"},
      {"step": 4, "band": "critical_range"}
    ]
  }
}
```

## Example MCP client config

Example local config shape for MCP-compatible clients:

```json
{
  "mcpServers": {
    "cml-agent-audit": {
      "command": "cml-mcp",
      "args": []
    }
  }
}
```

Alternative using Python module execution:

```json
{
  "mcpServers": {
    "cml-agent-audit": {
      "command": "python",
      "args": ["-m", "cml.integrations.mcp.server"]
    }
  }
}
```

Exact config file locations differ by client. Consult the MCP-compatible client documentation you use.

## Suggested prompt for an MCP client

```text
Use the CML MCP server to audit this agent trace.
Report whether the causal chain is valid, list findings, and explain any Cause Band drift.
```

## Relationship to existing demos

You can run the same Cause Band sidecar example without MCP:

```bash
python scripts/run_experimental_cause_band_eval.py examples/agent_intent_drift_trace.json --json
```

The MCP server exposes similar logic through tool calls so agent clients can invoke it directly.

## Current boundary

This integration does not claim:

- production prompt-injection detection,
- enforcement or blocking,
- autonomous policy rewriting,
- compliance certification,
- stable Cause Band semantics,
- hosted service availability.

It is a local developer-facing integration skeleton for CML agent-audit workflows.

## Next steps

Potential follow-up work:

1. Add file-based trace loading tool.
2. Add a dedicated `evaluate_agent_trace_sidecar` tool.
3. Add client-specific setup docs.
4. Add example screenshots or short demo video.
5. Add hosted transport only after local usage is validated.
