# OpenTelemetry GenAI × CML — bounded prototype v0

Status: experimental, read-only; no production integration or external submission.
Base CML revision: `2d961896ca527e44f57b240041f173106821563d` (package 0.4.0).
Source review: 25 November 2026.

## Research question

Can a successful GenAI tool span be correlated with independently supplied CML
records without manufacturing authority from telemetry?

Existing CML work: [integration opportunities, issue #79](https://github.com/safal207/Causal-Memory-Layer/issues/79),
[research note](../research/HIGH_VALUE_INTEGRATION_OPPORTUNITIES.md), and
[approval-lineage demo](../../examples/agent_approval_lineage_audit.py).
This prototype implements only the narrow post-hoc correlation seam. It is not
a second observability system or a new audit engine. Targeted searches for
OpenTelemetry/otel/GenAI code, PRs, issues and branches did not identify an
existing executable adapter; this is not an exhaustive history scan.

## Upstream architecture

- [GenAI tool execution semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/execute-tool.md)
  (Development; reviewed on the date above): tool execution spans use
  `gen_ai.operation.name=execute_tool`, tool name, and provider tool-call ID
  when available. The separate GenAI repository is the current source; the
  legacy semantic-conventions registry marks moved entries deprecated.
- [Trace data model](https://opentelemetry.io/docs/specs/otel/trace/data-model/):
  trace/span IDs, parent relationships and links support execution correlation.
  They are not independent authority evidence.
- [Tracing API](https://opentelemetry.io/docs/specs/otel/trace/api/):
  UNSET is normal for successful instrumentation; OK is not required for
  success. Neither OK nor UNSET is a permission or outcome proof.
- [Recent instrumentation guidance](https://opentelemetry.io/blog/2026/agent-harness-genai-instrumentation/)
  illustrates execute-tool instrumentation and semantic convention validation.

The upstream documentation is a dated review of moving pages, not a pinned
conformance claim. The prototype accepts only a small profile of existing
fields; it does not add official GenAI semantic attributes.

## Data flow and trust boundary

```text
finished SDK ReadableSpan -> allowlisted observation
                              |
trusted host binding ---------+ (trace ID, span ID, tool name, call ID)
                              |
trusted CML records ----------+ -> target's ancestry -> CML AuditEngine
                              |
                     observed status + bounded lineage result
```

| Input | Purpose | Not inferred |
|---|---|---|
| trace ID + span ID | Identify a specific observed span | authorization |
| tool name + provider call ID | Match a host-provided binding | globally unique logical operation or idempotency |
| span status | Report what the instrumentation recorded | external effect, permission, or success if UNSET |
| SpanBinding | Trusted host correlation to a CML record | identity or signature verification by this adapter |
| CausalRecord sequence | Host-supplied ancestry | authenticity or completeness from tracing alone |

The adapter does not copy prompt content, arguments, results, baggage, links
or arbitrary authority attributes. IDs and tool names may still be sensitive;
use synthetic data and handle identifiers under applicable retention rules.

The host must authenticate the source records and bind the exact action,
including any payload, target, scope and approval freshness checks required by
the application. Those checks are outside v0. Host trust is an assumption,
not a guarantee made by this prototype.

## Reproduce

From this branch in a virtual environment (Python 3.10–3.12 supported by CML):

```bash
python -m pip install -e ".[dev]"
python -m pytest -q tests/test_otel_genai_adapter.py
```

The main test matrix uses small SDK-shaped fixtures, the actual CML audit
engine and deterministic synthetic records. A required development-suite SDK smoke test
creates real spans in an in-memory exporter, without network access:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q tests/test_otel_genai_adapter.py
```

The development extra pins opentelemetry-sdk==1.45.2. The test checks that exact version and fails if the SDK is absent or mismatched. Production dependencies are unchanged. The real span test exercises supported ancestry, missing approval, missing binding and mismatched call identity.

The core matrix checks equal observed status with/without approval, forged
attributes, correlation mismatches, missing call ID, missing/duplicate record,
cycle, temporal inversion, invalid spans, unsupported actions and unrelated
approval. Expected lineage outcomes:

| Synthetic observation | Host-side evidence | Expected lineage |
|---|---|---|
| OK / UNSET / ERROR | linked explicit root and human approval | LINEAGE_SUPPORTED |
| OK | connected ancestry without required approval | LINEAGE_NOT_SUPPORTED |
| OK | missing causal parent | LINEAGE_NOT_SUPPORTED |
| OK | no binding or mismatched span/call identity | INDETERMINATE |

A missing call ID is valid for some upstream instrumentations, but v0 cannot
correlate it without a separate profile. Malformed or unsupported spans raise
ValueError instead of yielding a positive result.

## Non-claims / follow-up

No dispatch, production data, external effects, authorization grant, live
policy enforcement, OTLP collector integration, distributed completeness,
sampling recovery, signature verification, freshness enforcement or replay
prevention. CML's existing rules check supplied evidence; they do not prove
that a missing sampled span means an unauthorized action occurred. No claim
of compliance with the entire OpenTelemetry GenAI specification.

Next gate: verify exact-head CI and the required real SDK smoke test, inspect
false-positive/negative cases with an independent reviewer, pin the upstream
semantic convention revision and SDK, then decide whether a richer adapter
is justified. No external outreach or merge is authorized by this artifact.
