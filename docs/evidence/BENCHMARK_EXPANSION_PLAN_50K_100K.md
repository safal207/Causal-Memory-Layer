# Benchmark Expansion Plan for a $50k–$100k Grant

Status: grant-scale benchmark plan.

Purpose: explain how CML can grow from the current deterministic benchmark into a stronger reviewer-facing evaluation package suitable for a larger open-source AI safety grant.

## Current baseline

CML already has a deterministic benchmark snapshot:

```text
Total cases: 6
Matched cases: 6
Mismatches: 0
Expected passed / failed: 3 / 3
Predicted passed / failed: 3 / 3
```

Current benchmark assets:

- `scripts/run_safety_eval.py`
- `benchmarks/fixtures/`
- `benchmarks/RESULTS.md`
- `docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md`

This is enough to show that the current audit rules can reproduce selected causal-validity findings.

For a $50k–$100k grant, the benchmark should become more systematic, externally reproducible, and easier to compare across CML versions and adjacent agent trace systems.

## Target outcome

By the end of the grant period, CML should have:

```text
30–50 deterministic benchmark fixtures
10–12 documented causal failure classes
machine-readable expected findings
versioned benchmark reports
external validation notes from at least 2 independent reviewers or contributors
clear non-claims and limits
```

The goal is not to claim complete AI safety. The goal is to make one safety primitive measurable:

```text
Can CML distinguish operational success from causal legitimacy in structured action traces?
```

## Benchmark dimensions

The expanded benchmark should cover these dimensions:

| Dimension | Example question |
| --- | --- |
| Parent validity | Does every sensitive action have a valid parent cause? |
| Root authority | Is the root authority explicit, well-formed, and unambiguous? |
| Causal gaps | Are missing handoffs explicitly marked instead of silently hidden? |
| Secret-to-network lineage | Is sensitive access causally connected to outbound behavior? |
| Delegated authority | Does permission survive a human-to-agent or agent-to-agent handoff? |
| Policy scope | Was the action inside the permitted data or tool scope? |
| Stale cause reuse | Did the system reuse an old approval for a new action? |
| Branch contamination | Did a rejected or unrelated branch influence the current action? |
| Multi-tenant boundary | Did the action cross domain/customer/project boundaries? |
| CTAG integrity | Are compact causal tags malformed, stale, or mismatched? |
| Exception handling | Is an exception path explicitly approved and auditable? |
| Recovery path | Does rollback or remediation preserve responsibility lineage? |

## Proposed fixture groups

### Group A — current core rules

- valid grounded chain;
- missing parent;
- unmarked gap;
- ambiguous root;
- secret-to-network missing chain;
- custom network action outside session ancestry.

### Group B — agentic workflow failures

- stale parent cause reused from an old task;
- valid-looking local action inside invalid thread context;
- rejected branch reused after human rejection;
- memory-derived claim with missing evidence parent;
- delegated agent action with missing authority handoff.

### Group C — fintech / high-stakes workflow failures

- credit-limit recommendation using restricted PII scope;
- transaction review with expired policy version;
- human approval required but absent;
- audit record references wrong customer/account boundary;
- escalation path missing reviewer responsibility chain.

### Group D — security / data boundary failures

- secret read followed by delayed network egress;
- cross-tenant file access with valid-looking local parent;
- API key access without approved tool call parent;
- sensitive file copied to outbound job with broken lineage;
- recovery action that loses original cause.

### Group E — positive controls

Every failure class should have at least one valid counterpart so the benchmark does not only test failures.

Examples:

- valid delegated authority chain;
- valid explicit exception approval;
- valid human-supervised fintech recommendation;
- valid secret-to-network path with approved scope;
- valid remediation chain preserving original responsibility.

## Expected benchmark metadata

Each fixture should have a machine-readable expectation file or embedded metadata:

```json
{
  "fixture_id": "stale_parent_cause_001",
  "category": "agentic_workflow",
  "expected_passed": false,
  "expected_findings": [
    "CML-AUDIT-R6-STALE_PARENT_CAUSE"
  ],
  "safety_claim": "Detects reuse of old authorization in a new action context.",
  "non_claims": [
    "Does not prove all stale memory failures are detected.",
    "Does not replace runtime policy enforcement."
  ]
}
```

## Report outputs

The benchmark runner should be able to generate:

```text
benchmarks/RESULTS.md
benchmarks/RESULTS.json
benchmarks/reports/<date>-benchmark-report.md
```

Suggested report sections:

- benchmark version;
- CML version / commit SHA;
- Python version and environment;
- fixture count;
- matched / mismatched cases;
- findings by category;
- new / changed rules;
- known limitations;
- interpretation for safety reviewers.

## Evaluation milestones

### Milestone 1 — benchmark taxonomy

Deliverables:

- documented failure taxonomy;
- 10–12 failure classes;
- naming convention for fixture IDs;
- expected finding metadata format.

### Milestone 2 — expanded fixtures

Deliverables:

- 30–50 fixtures;
- positive and negative controls;
- updated benchmark results;
- regression tests for expected findings.

### Milestone 3 — benchmark report generation

Deliverables:

- Markdown report generation;
- JSON result export;
- summary tables for grant reviewers;
- stable reproduction commands.

### Milestone 4 — external validation

Deliverables:

- independent reviewer run protocol;
- at least 2 external validation notes;
- environment snapshots;
- reported mismatches or reproduction issues tracked as issues.

### Milestone 5 — technical report

Deliverables:

- short technical report;
- benchmark methodology;
- causal failure taxonomy;
- results and limitations;
- future research directions.

## Budget fit

A $50k–$100k grant is reasonable if it funds:

| Workstream | Scope |
| --- | --- |
| Benchmark engineering | fixture expansion, metadata, report generation |
| Research taxonomy | causal invalidity classes and rule definitions |
| API/demo hardening | Docker, local validation, reproducibility |
| External validation | reviewer protocol, result collection, issue follow-up |
| Technical report | methodology, results, non-claims, publication-ready summary |

## Success criteria

The upgraded benchmark should let a reviewer say:

```text
I can reproduce CML's current causal-validity findings locally,
see what failure classes are covered,
inspect expected findings,
and understand what the benchmark does and does not prove.
```

That is the evidence threshold that makes a $50k–$100k ask more credible than a small maintenance grant.
