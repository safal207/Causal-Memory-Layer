# CML Reviewer-Ready Snapshot Notes

Status: reviewer-ready documentation snapshot.

This document summarizes the current CML state for OpenAI, grant, and external reviewers.

## Snapshot summary

CML is an open-source causal audit layer for structured action traces.

Its current reviewer-safe thesis is:

```text
Logs show what happened. CML checks why it was allowed.
```

The project is intentionally narrow:

```text
causal-validity checking for structured action traces
```

## Current reviewer claim

Reviewer-safe claim:

```text
CML provides a deterministic causal-audit scaffold for checking permission and responsibility lineage in structured action traces.
```

Do not overstate this as full AI alignment, production compliance, certified security, or universal agent governance.

## Recent reviewer-ready upgrades

### Portfolio positioning

Added:

```text
docs/PORTFOLIO_RELATIONSHIP.md
```

CML is now explicitly positioned inside the broader trustworthy-agent evidence architecture:

```text
PythiaLabs — pre-execution evidence gates
LTP — path-level trace/replay/admissibility
CML — causal permission and responsibility lineage
DMP — decision memory and irreversibility governance
LRI — living identity and relational invariants
```

### Reviewer path

Added:

```text
docs/REVIEWER_PATH.md
```

This gives a short reading path for OpenAI, grant, and external reviewers.

### Non-claims

Added:

```text
docs/NON_CLAIMS.md
```

This explicitly states that CML does not claim:

- full AI alignment;
- certified compliance;
- production security certification;
- universal model evaluation;
- prevention of all unsafe actions;
- replacement of logs, tracing, SIEM, observability, policy engines, or human review;
- automatic truth discovery;
- complete agent governance.

### Research navigation

Added:

```text
docs/research/README.md
```

This gives a recommended reading order for research notes and evidence docs.

### API smoke tests

Added:

```text
tests/test_api_smoke.py
```

Coverage includes:

- `GET /health`;
- `POST /audit`;
- `POST /ctag/decode` valid input;
- `POST /ctag/decode` invalid input.

### Test dependency fix

Added `httpx>=0.27` to both `api` and `dev` optional dependencies in:

```text
pyproject.toml
```

Reason:

```text
fastapi.testclient.TestClient depends on Starlette TestClient, which requires httpx.
```

## Local validation recorded

The API smoke-test change was locally validated before being applied to `main`.

Recorded result:

```text
pip install -e ".[dev]" -> ok
pytest -> passed: 140 passed, 0 failed
python scripts/run_safety_eval.py -> passed: 6/6 matched
```

Note: local working tree dirtiness was reported as pre-existing and unrelated to PR #50.

## Current evidence anchors

| Evidence | Location |
|---|---|
| Reviewer path | `docs/REVIEWER_PATH.md` |
| Non-claims | `docs/NON_CLAIMS.md` |
| Portfolio relationship | `docs/PORTFOLIO_RELATIONSHIP.md` |
| Benchmark evidence snapshot | `docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md` |
| Tracked benchmark report | `benchmarks/RESULTS.md` |
| Docker walkthrough | `docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md` |
| Research navigation | `docs/research/README.md` |
| LTP / CML bridge | `docs/LTP_CML_BRIDGE.md` |
| External validation protocol | `docs/evidence/EXTERNAL_VALIDATION_PROTOCOL.md` |
| Security policy | `SECURITY.md` |
| Contributing guide | `CONTRIBUTING.md` |
| License | `LICENSE` |

## Open PR cleanup

Previously stale PRs were resolved:

- `#84` docs research navigation map — manually applied on current `main`.
- `#73` LTP/CML bridge — already satisfied on current `main`; closed.
- `#50` API smoke tests — manually applied with `httpx` dependency fix.

## Validation command

Recommended reviewer validation:

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

## Reviewer interpretation

CML should be evaluated as a focused infrastructure primitive, not as a full safety platform.

Correct interpretation:

```text
CML makes broken causal permission and responsibility lineage visible in structured action traces.
```

Incorrect interpretation:

```text
CML solves AI safety or compliance by itself.
```

## Funding relevance

CML is strongest as a second technical anchor after LTP.

Where LTP asks:

```text
Was the execution path grounded, replayable, and admissible?
```

CML asks:

```text
Why was this action allowed, and is the causal permission/responsibility chain intact?
```

Together, they make high-risk agent behavior more inspectable at both path and causal-legitimacy layers.

## Remaining recommended hardening

Before a formal reviewer-ready tag, complete:

- clean-checkout validation on fresh clone;
- confirm benchmark/evidence docs still match generated results;
- optionally add a release tag after clean validation;
- optionally collect one external reviewer comment or issue specific to CML.

## Bottom line

CML is now substantially cleaner for external review:

```text
clear problem framing + reviewer path + non-claims + portfolio relationship + smoke tests + recorded validation
```

It is ready for the next step: clean-checkout validation and optional reviewer-ready tag.
