# CML $75k–$100k Grant Plan

Status: grant-scale execution plan.

Purpose: define a credible $75k–$100k funding ask for turning Causal Memory Layer (CML) from an early open-source causal audit artifact into a benchmark-backed, externally reproducible research prototype for causal-validity checking in agentic AI workflows.

## One-sentence ask

```text
We request $75k–$100k to expand CML into a reproducible benchmark and external-validation package for detecting causally invalid actions in agentic AI workflows.
```

## Short thesis

AI agents increasingly perform actions, not only generate text. In high-stakes workflows, an action can succeed operationally while lacking valid authorization, approval, intent, or responsibility lineage.

CML addresses this gap by checking whether structured action traces preserve causal legitimacy:

```text
What happened is not enough.
We need to know why it was allowed.
```

## Current baseline

CML already has:

- a Python causal validation and audit engine;
- causal chain reconstruction utilities;
- CLI and API surfaces;
- deterministic benchmark fixtures;
- tracked benchmark results;
- Docker demo walkthrough;
- grant evidence package;
- explicit non-claims;
- LTP / CML architecture bridge;
- reviewer checklist.

Current benchmark baseline:

```text
Total cases: 6
Matched cases: 6
Mismatches: 0
Expected passed / failed: 3 / 3
Predicted passed / failed: 3 / 3
```

This is a credible seed artifact. The grant funds the next step: systematic benchmark expansion, independent validation, and a technical report.

## What the grant will produce

By the end of the grant period, CML should produce:

```text
30–50 deterministic benchmark fixtures
10–12 causal invalidity failure classes
machine-readable expected findings
Markdown + JSON benchmark reports
2–5 external validation notes
Docker-based reproducibility path
short technical report
clear benchmark limitations and non-claims
```

## Why $75k–$100k is justified

A smaller grant can fund maintenance and documentation.

A $75k–$100k grant funds a complete evidence package:

```text
benchmark taxonomy
fixture expansion
expected finding metadata
report generation
external validation
technical report
API/demo hardening
integration boundary docs
```

The value is not only code. The value is producing a reusable evaluation artifact that other researchers and engineers can run, inspect, critique, and extend.

## Workstreams

### Workstream 1 — Benchmark taxonomy and fixture expansion

Goal:

```text
Move from 6 curated fixtures to 30–50 benchmark fixtures across 10–12 causal failure classes.
```

Deliverables:

- documented causal invalidity taxonomy;
- fixture naming convention;
- positive and negative controls;
- expected finding metadata;
- expanded `benchmarks/fixtures/` suite;
- updated `benchmarks/RESULTS.md`.

Candidate failure classes:

- missing parent cause;
- ambiguous root authority;
- unmarked causal gap;
- secret-to-network missing lineage;
- stale parent cause reused from old workflow;
- invalid delegated authority;
- rejected branch reused;
- cross-tenant or cross-domain boundary violation;
- expired policy context;
- restricted data scope usage;
- missing human approval;
- valid exception path with explicit approval.

### Workstream 2 — Benchmark runner and report generation

Goal:

```text
Make benchmark outputs easy to reproduce, compare, and cite.
```

Deliverables:

- stable Markdown report generation;
- JSON result export;
- benchmark version metadata;
- commit SHA and environment metadata;
- mismatch reporting;
- category-level summary tables.

Target output paths:

```text
benchmarks/RESULTS.md
benchmarks/RESULTS.json
benchmarks/reports/<date>-benchmark-report.md
```

### Workstream 3 — External validation package

Goal:

```text
Show that reviewers outside the project can reproduce CML results from public instructions.
```

Deliverables:

- validation protocol;
- clean environment instructions;
- external validation note template;
- 2–5 validation notes from independent reviewers or contributors;
- issues created for reproduction problems;
- clear limitations.

Reference:

```text
docs/evidence/EXTERNAL_VALIDATION_PROTOCOL.md
```

### Workstream 4 — Docker/API demo hardening

Goal:

```text
Make the demo path reviewer-friendly and reliable on common local environments.
```

Deliverables:

- Docker walkthrough validation;
- API response examples;
- clearer local troubleshooting;
- sample payloads;
- minimal reproducibility scripts;
- no hosted-service dependency.

Reference:

```text
docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md
```

### Workstream 5 — Technical report

Goal:

```text
Publish a short technical report explaining the model, benchmark method, results, and limitations.
```

Deliverables:

- technical report draft;
- abstract;
- problem statement;
- CML model and audit rules;
- benchmark methodology;
- current and expanded results;
- external validation summary;
- limitations and non-claims;
- future work.

Reference:

```text
docs/research/TECHNICAL_REPORT_OUTLINE.md
```

### Workstream 6 — Integration boundaries

Goal:

```text
Clarify how CML relates to LTP, T-Trace, CaPU, TTM DB, logs, observability, and runtime policy systems.
```

Deliverables:

- updated architecture bridge docs;
- trace adapter boundary notes;
- non-overlap with observability and SIEM systems;
- policy hook roadmap;
- grant-safe claim language.

## Budget model

### $75k ask

| Category | Amount | Purpose |
| --- | ---: | --- |
| Benchmark expansion | $25k | taxonomy, fixtures, expected findings, positive/negative controls |
| Runner/reporting | $12k | JSON/Markdown reports, metadata, mismatch summaries |
| External validation | $12k | protocol, validator support, reproduction issue handling |
| Docker/API hardening | $8k | walkthrough reliability, payloads, demo scripts |
| Technical report | $10k | methodology, results, limitations, publication-quality draft |
| Maintenance/community | $8k | contributor review, docs polish, CI support |

### $100k ask

| Category | Amount | Purpose |
| --- | ---: | --- |
| Benchmark expansion | $32k | 50 fixtures, 12 failure classes, stronger controls |
| Runner/reporting | $15k | richer reports, version comparison, machine-readable outputs |
| External validation | $18k | 3–5 validators, validation notes, reproduction issue loop |
| Docker/API hardening | $10k | stronger local demo, API examples, troubleshooting |
| Technical report | $15k | full technical report + publishable artifact |
| Integration boundary docs | $5k | LTP/T-Trace/CaPU boundary clarity |
| Maintenance/community | $5k | contributor coordination and review |

## Milestones

### Month 1 — taxonomy and benchmark design

Deliverables:

- causal invalidity taxonomy;
- fixture metadata format;
- initial 12–15 fixtures;
- first benchmark report format.

### Month 2 — fixture expansion and report generation

Deliverables:

- 25–35 fixtures;
- positive and negative controls;
- Markdown + JSON benchmark outputs;
- mismatch reporting;
- updated benchmark snapshot.

### Month 3 — external validation and demo hardening

Deliverables:

- external validation protocol used by independent reviewers;
- 2 validation notes minimum;
- Docker walkthrough improvements;
- reproduction issues tracked and addressed.

### Month 4 — technical report and final package

Deliverables:

- 30–50 fixtures;
- final benchmark report;
- external validation summary;
- technical report draft;
- grant-facing final evidence index.

## Success criteria

A successful grant outcome means a reviewer can say:

```text
I can run CML locally, reproduce benchmark findings, inspect expected results,
read external validation notes, and understand exactly what the benchmark proves
and does not prove.
```

Measurable targets:

- `pytest` passes in clean environment;
- benchmark runner produces stable results;
- 30–50 fixtures exist;
- each fixture has expected findings;
- benchmark reports include commit/environment metadata;
- 2–5 external validation notes exist;
- technical report draft exists;
- non-claims remain explicit.

## What this grant does not claim

This grant does not claim that CML will:

- solve AI alignment;
- provide certified compliance;
- replace production IAM, SIEM, EDR, or observability stacks;
- prevent all unsafe actions;
- prove a deployed AI system is safe.

The funded claim is narrower:

```text
CML will provide a reproducible benchmark-backed research prototype for causal-validity checking in structured agentic action traces.
```

## Best grant ask wording

For $75k:

```text
We request $75,000 to expand CML into a benchmark-backed, externally reproducible research artifact for causal-validity checking in agentic AI workflows, including 30–50 fixtures, report generation, external validation notes, and a technical report.
```

For $100k:

```text
We request $100,000 to produce a more complete open-source causal-validity evaluation package for agentic AI workflows, including expanded benchmarks, machine-readable expected findings, external validation across multiple reviewers, Docker/API reproducibility, and a publication-ready technical report.
```

## Bottom line

The $75k–$100k case is credible if the application frames CML as:

```text
open-source AI safety research infrastructure
for reproducible causal-validity evaluation,
not as a finished production compliance platform.
```
