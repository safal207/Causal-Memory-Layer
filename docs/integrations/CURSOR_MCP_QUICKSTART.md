# Cursor MCP Quickstart for CML Agent Audit

## Status

This is a quickstart for trying the experimental CML MCP server from an MCP-compatible coding assistant workflow.

The exact Cursor UI and config file location may change over time. Treat this document as a local setup recipe and adjust the MCP configuration location according to your installed Cursor version.

## Goal

Get from zero to a useful local agent-audit workflow:

```text
install CML with MCP extra
-> run one-command local demo
-> start cml-mcp
-> connect Cursor or another MCP-compatible client
-> ask the client to audit a trace
-> receive CML findings / Cause Band diagnostics
```

## One-command local demo

Before configuring an MCP client, run the same demo payloads through the MCP core tool logic:

```bash
python scripts/run_mcp_demo_payloads.py
```

This prints:

```text
health
audit_trace
evaluate_cause_band
```

Use this to confirm the demo payloads and CML logic work before connecting Cursor or another MCP-compatible client.

## Demo payloads

Ready-to-copy demo payloads live in:

```text
examples/mcp/audit_trace_missing_parent.json
examples/mcp/evaluate_cause_band_degrading.json
```

Use these files when you want to try the MCP tools without copying JSON from this document manually.

## 1. Install CML with MCP support

From the repository root:

```bash
pip install -e ".[mcp]"
```

For development:

```bash
pip install -e ".[dev,mcp]"
```

## 2. Verify the server command

Run:

```bash
cml-mcp
```

Alternative module form:

```bash
python -m cml.integrations.mcp.server
```

The MCP server uses stdio transport by default through the Python MCP SDK wrapper.

## 3. Add MCP config to your client

Example config shape:

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

Alternative module form:

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

If your client runs from a different working directory or virtual environment, use absolute paths.

Example:

```json
{
  "mcpServers": {
    "cml-agent-audit": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["-m", "cml.integrations.mcp.server"]
    }
  }
}
```

## 4. Confirm available tools

After the client connects, ask:

```text
Use the CML MCP server health tool and tell me what tools are available.
```

Expected tools:

```text
health
audit_trace
evaluate_cause_band
```

## 5. Try core causal audit

Fast path:

```text
Use the CML MCP server to call audit_trace with examples/mcp/audit_trace_missing_parent.json.
Explain the result in plain English.
```

Manual payload:

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
    },
    {
      "id": "child",
      "timestamp": 2,
      "actor": {"pid": 100, "uid": 1000},
      "action": "open",
      "object": "/tmp/readme.txt",
      "permitted_by": "fs:read",
      "parent_cause": "missing-parent"
    }
  ]
}
```

Expected finding:

```text
CML-AUDIT-R1-MISSING_PARENT
```

Plain-language meaning:

```text
The second action points to a parent cause that does not exist in the trace.
```

## 6. Try Cause Band evaluation

Fast path:

```text
Use the CML MCP server to call evaluate_cause_band with examples/mcp/evaluate_cause_band_degrading.json.
Explain the trajectory diagnostics and predicted codes.
```

Manual payload:

```json
{
  "cause_band_sidecar": {
    "case_id": "cursor-cause-band-demo",
    "status": "experimental",
    "cause_band_policy": {
      "duration_threshold": "3_steps"
    },
    "trajectory": [
      {"step": 1, "band": "safe_range"},
      {"step": 2, "band": "warning_range"},
      {"step": 3, "band": "danger_range"},
      {"step": 4, "band": "critical_range"}
    ],
    "expected_future_cause_band_behavior": {
      "expected_codes": [
        "CML-AUDIT-RANGE-DRIFT",
        "CML-AUDIT-RANGE-PERSISTENT_DEVIATION",
        "CML-AUDIT-RANGE-CRITICAL_EXIT"
      ]
    }
  }
}
```

Expected diagnostics:

```text
trajectory_direction = degrading
recovered_to_safe = false
oscillating = false
max_consecutive_outside_safe = 3
```

Expected findings:

```text
CML-AUDIT-RANGE-DRIFT
CML-AUDIT-RANGE-PERSISTENT_DEVIATION
CML-AUDIT-RANGE-CRITICAL_EXIT
```

## 7. Suggested prompt for Cursor

```text
Use the CML MCP server to audit this agent trace.
First call health.
Then call audit_trace with examples/mcp/audit_trace_missing_parent.json.
Explain the findings in plain English and mention whether the trace passed.
```

For Cause Band:

```text
Use the CML MCP server to evaluate examples/mcp/evaluate_cause_band_degrading.json.
Explain trajectory_direction, recovered_to_safe, oscillating, and predicted_codes.
```

## 8. What this quickstart proves

This proves a small but important product path:

```text
an agent builder can connect CML as a local audit tool
and ask an AI coding client to inspect causal traces.
```

It does not prove production safety.

## Safety boundary

Do not connect this experimental local server to untrusted remote clients.

Do not treat CML MCP output as enforcement.

Do not let an agent automatically rewrite policy based only on one audit result.

Recommended review loop:

```text
agent proposes action trace
-> CML audits trace
-> human reviews findings
-> policy/test changes happen through normal code review
```

## Troubleshooting

### The client cannot find `cml-mcp`

Use the Python module form with an absolute Python path:

```json
{
  "mcpServers": {
    "cml-agent-audit": {
      "command": "/absolute/path/to/python",
      "args": ["-m", "cml.integrations.mcp.server"]
    }
  }
}
```

### The client connects but shows no tools

Restart the client after editing MCP config.

Then ask it to call:

```text
health
```

### The audit tool rejects the payload

`audit_trace` expects either:

```text
{"records": [...]}
```

or a top-level list of CML records.

Each record must include:

```text
id
timestamp
actor
action
object
permitted_by
```

`actor` must include:

```text
pid
uid
```

## Related docs

```text
docs/integrations/MCP_AGENT_AUDIT.md
docs/demo/AGENT_INTENT_DRIFT_CAUSE_BAND_EXAMPLE.md
docs/research/CML_RESEARCH_MAP.md
```
