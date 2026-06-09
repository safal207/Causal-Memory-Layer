# Cyber agent approval audit demo

This walkthrough shows how CML can audit a defensive security-agent workflow that moves from read-only patch review into higher-risk agent actions.

The example is synthetic. It models action records and approval lineage only. It does not provide offensive instructions, runnable attack logic, target details, or vulnerability exploitation steps.

## Why this matters

Security agents can read patches, summarize risk, prepare test artifacts, and call execution tools faster than a human can manually inspect every step.

Ordinary logs can show that a tool call happened. CML asks a narrower accountability question:

```text
Was this high-risk action causally permitted by a valid approval chain?
```

The key distinction:

```text
The action may succeed operationally,
but still be causally invalid.
```

## Modeled workflow

The demo models this trace:

```text
human task
→ read patch
→ write risk analysis
→ prepare synthetic high-risk test artifact
→ run synthetic artifact in sandbox
```

Read-only analysis is allowed to descend from the original human task. The high-risk transitions require stronger lineage:

| Action | CTAG class | Required ancestor |
| :--- | :--- | :--- |
| `generate_poc` | `ML_ACTION` | `OVERRIDE` with `policy_approval:` |
| `exec` | `EXEC` | `OVERRIDE` with `human_approval:` |

## Run the demo

```bash
python examples/cyber_patch_to_poc_audit.py
```

The script runs two traces:

1. an invalid trace where high-risk artifact preparation and sandbox execution lack the required approval ancestors;
2. a valid trace where the same actions are connected to policy and human approvals.

## Expected invalid findings

```text
CML-AUDIT-R7-ML_ACTION_REQUIRES_POLICY_APPROVAL
CML-AUDIT-R5-EXEC_REQUIRES_HUMAN_APPROVAL
```

These findings mean that the trace is structurally connected, but the sensitive steps do not descend from the approval records required by the configured cyber-audit rules.

## Expected valid result

```text
PASS: high-risk actions have valid causal approval lineage.
```

## What this demonstrates

CML is not a scanner, policy engine, or runtime blocker by itself.

It contributes a focused audit primitive:

```text
causal-validity checking for structured action traces
```

For cyber-agent workflows, this makes it possible to review whether a sensitive action had a valid upstream policy or human approval chain, not merely whether the action was executed successfully.
