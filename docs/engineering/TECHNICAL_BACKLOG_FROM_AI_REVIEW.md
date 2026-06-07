# Technical Backlog from AI Engineering Review

This document converts an AI-assisted technical review of `audit.py`, `chain.py`, benchmarks, packaging, and roadmap into a concrete engineering backlog.

It is not an independent external validation. It is an internal planning artifact.

## Review correction notes

Some review points were already resolved or need narrowing.

### Publishing status

The review mentioned Trusted Publisher / TestPyPI as an unresolved issue.

That is now outdated.

Current status:

- TestPyPI publication: passed.
- Production PyPI publication: passed.
- Production PyPI install smoke test: passed.
- README install section: updated.
- PyPI release issues: closed as completed.

Evidence:

```text
https://pypi.org/project/causal-memory-layer/0.4.0/
https://github.com/safal207/Causal-Memory-Layer/actions/runs/27101272184/job/79982287069
```

### Performance / ancestors caching

The review suggested caching ancestors for larger logs.

Current code already has some targeted caching / precomputation:

- R3 precomputes ancestor sets per NET_OUT action.
- Custom rules use a lazy `_anc_cache` keyed by record id.

Still useful future work:

- add explicit large-log benchmarks,
- document complexity expectations,
- add optional indexing / graph-store strategy for larger traces.

### Cause Band stability

The review suggested moving Cause Band toward stable.

Current recommendation: keep Cause Band experimental until there are:

- stable semantics,
- more fixtures,
- clear non-claims,
- reviewer-facing examples,
- performance and false-positive notes.

Do not promote it to stable only because it is conceptually exciting.

## High-priority engineering backlog

### 1. Add large-log performance benchmark

Goal:

```text
Measure AuditEngine behavior on 1k / 10k / 50k synthetic records.
```

Why:

- validates scalability claims,
- supports grant and integration conversations,
- identifies whether graph-store work is needed soon.

Suggested deliverables:

- `benchmarks/performance/generate_large_trace.py`
- `benchmarks/performance/run_large_trace_benchmark.py`
- `benchmarks/performance/RESULTS.md`

Acceptance criteria:

- benchmark is deterministic,
- outputs total records, findings, runtime, and rough memory notes,
- does not claim production-scale performance without evidence.

### 2. Add finding context / chain snippet support

Goal:

```text
Make findings easier to understand by including optional causal context.
```

Potential API:

```text
Finding.chain_ids
Finding.context
```

Use cases:

- show parent chain around a failure,
- help reviewers understand why `MISSING_PARENT` fired,
- improve CLI and docs examples.

Acceptance criteria:

- context is optional,
- existing `Finding.to_dict()` remains backwards-compatible,
- tests cover at least R1 and R3 context.

### 3. Refactor audit rules without changing behavior

Goal:

```text
Split AuditEngine rule checks into smaller internal methods.
```

Candidates:

- `_check_reference_integrity()` for R1,
- `_check_root_and_gap_marking()` for R2/R4,
- `_check_secret_net_chain()` for R3,
- `_check_custom_rules()` for R5+,
- `_check_experimental_cause_band()`.

Acceptance criteria:

- no behavior change,
- benchmark remains `6/6 matched`,
- tests remain green.

### 4. Add automatic versioning plan

Goal:

```text
Decide whether to keep explicit versioning or adopt setuptools_scm.
```

Important:

- do not switch hastily after first PyPI release,
- evaluate compatibility with release workflow,
- document the release versioning policy.

Suggested deliverable:

```text
docs/release/VERSIONING_POLICY.md
```

### 5. Add integration backlog for agent frameworks

Goal:

```text
Prepare optional examples for agent frameworks without adding core dependencies.
```

Candidates:

- CrewAI-style traces — already started,
- LangGraph-style state transition traces,
- AutoGen-style multi-agent message/tool traces,
- MCP agent-audit flows.

Acceptance criteria:

- examples are optional,
- dependency-light,
- no framework dependency in CML core,
- each example has explicit non-claims.

### 6. Keep Cause Band experimental and expand evidence

Goal:

```text
Build stronger evidence before promoting Cause Band semantics.
```

Suggested deliverables:

- more fixtures,
- false-positive / false-negative notes,
- stable terminology document,
- comparison with baseline CML causal parent rules.

Acceptance criteria:

- remains opt-in,
- docs say non-normative / experimental,
- no production safety overclaim.

## Lower-priority backlog

### Rule registry

A dynamic rule registry may be useful later, but it should wait until the existing rule surface is stable.

Do first:

- refactor rule methods,
- add tests,
- add finding context,
- add performance benchmark.

Then consider:

```text
RuleRegistry
RulePlugin
YAML-loaded rule modules
```

### Graph database / persistent trace store

Neo4j or another graph backend may be useful for long-term trace storage, but it should not be added before measuring real performance pressure.

Recommended order:

1. synthetic large-log benchmark,
2. document memory/runtime behavior,
3. prototype storage adapter,
4. only then evaluate graph databases.

## Suggested next issue set

Create issues for:

1. `perf: add deterministic large-log benchmark for AuditEngine`
2. `feat: add optional finding context / chain snippets`
3. `refactor: split AuditEngine rules into internal methods`
4. `docs: add release versioning policy`
5. `docs: add integration backlog for agent frameworks`
6. `research: expand Cause Band evidence before stabilization`

## Strategic recommendation

Do not refactor core code only for elegance right now.

The highest-value next step is:

```text
performance evidence + clearer finding context + optional agent-framework examples
```

This supports:

- grant applications,
- external integrations,
- reviewer trust,
- future production-readiness discussion.
