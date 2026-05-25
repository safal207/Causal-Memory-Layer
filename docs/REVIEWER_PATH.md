# CML Reviewer Path

Status: reviewer-facing navigation path.

This document gives a short reading path for OpenAI, grant, and external reviewers.

## One-sentence summary

CML is an open-source causal audit layer for checking whether structured actions were causally permitted, not only whether they happened.

## Core thesis

```text
Logs show what happened. CML checks why it was allowed.
```

A system may be functionally correct while being causally invalid.

## If you only have 5 minutes

Read:

1. `README.md`
2. `docs/PORTFOLIO_RELATIONSHIP.md`
3. `docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md`
4. `docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md`
5. `docs/NON_CLAIMS.md`

Then answer:

```text
Does CML add a distinct causal-permission layer beyond ordinary logs, tracing, and policy checks?
```

## Recommended reviewer sequence

1. Start with `README.md` for problem framing and quick validation.
2. Read `docs/PORTFOLIO_RELATIONSHIP.md` to understand how CML relates to LTP, PythiaLabs, DMP, and LRI.
3. Read `docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md` for the current deterministic evidence snapshot.
4. Run or inspect `docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md` for the fastest demo path.
5. Read `docs/research/CAUSAL_INVALIDITY_PATTERNS.md` for the failure taxonomy.
6. Read `docs/research/README.md` for the research-note navigation map.
7. Read `docs/NON_CLAIMS.md` for scope boundaries.

## What CML evaluates

CML focuses on structured action traces where permission, intent, approval, or responsibility lineage matters.

It asks:

```text
Why was this action allowed?
Is the parent cause present?
Is responsibility lineage intact?
Was authority malformed, missing, or ambiguous?
```

## What CML is distinct from

| System type | Usually answers | CML adds |
|---|---|---|
| Logs | What happened? | Whether the action had a valid causal parent. |
| Tracing | Where execution went. | Whether responsibility lineage survived the workflow. |
| Observability | What failed operationally. | What succeeded operationally but was causally invalid. |
| Policy checks | Whether something is allowed now. | Why this specific action was allowed in this trace. |
| Final-output review | Whether the result looks acceptable. | Whether the action path was causally legitimate. |

## Fast validation

```bash
pip install -e ".[dev]"
pytest
python scripts/run_safety_eval.py
```

Expected current result:

```text
pytest passes
safety eval: 6/6 matched
```

## Current evidence anchors

- Benchmark evidence snapshot: `docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md`
- Tracked benchmark report: `benchmarks/RESULTS.md`
- Benchmark runner: `python scripts/run_safety_eval.py`
- Docker walkthrough: `docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md`
- Research taxonomy: `docs/research/CAUSAL_INVALIDITY_PATTERNS.md`
- External validation protocol: `docs/evidence/EXTERNAL_VALIDATION_PROTOCOL.md`

## Current artifact surface

CML currently includes:

- Python causal validation and audit engine;
- causal chain reconstruction utilities;
- CLI commands for lineage validation and chain inspection;
- API layer and store interface;
- API smoke tests for health, audit, and CTAG decode;
- deterministic safety-eval benchmark fixtures and tracked results;
- Docker demo walkthrough;
- research and grant-facing documentation.

## Reviewer questions

A useful review should answer:

1. Is the problem framing clear?
2. Is causal validity meaningfully distinct from ordinary logging or policy checks?
3. Are the benchmark claims narrow enough?
4. Are the non-claims explicit enough?
5. Does the demo make the failure class understandable?
6. What evidence would make CML more fundable?

## Portfolio relationship

CML is one layer in a broader trustworthy-agent evidence architecture:

```text
PythiaLabs — pre-execution evidence gates
LTP — path-level trace/replay/admissibility
CML — causal permission and responsibility lineage
DMP — decision memory and irreversibility governance
LRI — living identity and relational invariants
```

CML's specific role:

```text
Validate why an action was allowed.
```

## Funding interpretation

CML is most fundable as a narrow infrastructure primitive:

```text
causal-validity checking for structured AI-agent and high-trust automation traces
```

It should not be presented as a full safety stack, compliance product, or production enforcement system.
