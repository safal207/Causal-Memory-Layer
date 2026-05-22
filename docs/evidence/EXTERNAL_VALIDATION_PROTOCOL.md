# External Validation Protocol

Status: reviewer-facing validation protocol.

Purpose: define how an independent reviewer, contributor, or grant evaluator can reproduce CML results and report whether the current artifact behaves as documented.

## Why external validation matters

For small grants, internal deterministic benchmarks may be enough to show that the project is real.

For a larger $50k–$100k grant, CML should also show that external reviewers can run the artifact, reproduce the findings, and report issues without private context.

This protocol is designed to make that possible while keeping claims narrow.

## What external validation should test

External validation should answer four questions:

1. **Can a clean user install and run CML?**
2. **Can the benchmark be reproduced locally?**
3. **Do documented demo commands work as written?**
4. **Are CML findings understandable without reading the full source code?**

External validation does not prove production safety, compliance, or complete security coverage.

## Reviewer profile

Good external validators include:

- open-source contributors;
- AI safety researchers;
- QA / test engineers;
- security or compliance engineers;
- infra engineers familiar with traces, logs, or audit systems;
- grant reviewers who can run local Python/Docker commands.

No private credentials or hosted services should be required.

## Minimal validation path

A validator should use a clean environment when possible.

### Step 1 — Clone repository

```bash
git clone https://github.com/safal207/Causal-Memory-Layer.git
cd Causal-Memory-Layer
```

### Step 2 — Install dev dependencies

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

### Step 3 — Run tests

```bash
pytest
```

Record:

```text
Python version:
OS:
Commit SHA:
pytest result:
Failures, if any:
```

### Step 4 — Run safety benchmark

```bash
python scripts/run_safety_eval.py
```

Record:

```text
Total cases:
Matched cases:
Mismatches:
Expected passed / failed:
Predicted passed / failed:
```

### Step 5 — Run Docker demo

```bash
docker compose up --build
```

Then follow:

```text
docs/demo/DOCKER_CAUSAL_MEMORY_WALKTHROUGH.md
```

Record:

```text
Docker version:
Compose version:
Health endpoint result:
Broken-chain audit result:
Valid-chain audit result:
Problems encountered:
```

## Optional deeper validation

A deeper validator can also inspect:

- `docs/evidence/BENCHMARK_EVIDENCE_SNAPSHOT.md`
- `benchmarks/fixtures/`
- `benchmarks/RESULTS.md`
- `docs/audit/FINDINGS_GLOSSARY.md`
- `docs/GRANT_REVIEWER_CHECKLIST.md`

They can ask:

- Are expected findings named consistently?
- Do docs avoid overclaiming?
- Are reproduction commands copy-pasteable?
- Are failure classes understandable?
- Are limitations explicit?

## External validation note format

Validators can report results in an issue, PR comment, or standalone Markdown note.

Suggested format:

```md
# External Validation Note

Validator: <name or handle>
Date: <YYYY-MM-DD>
Repository commit: <SHA>
Environment:
- OS:
- Python:
- Docker:

## Commands run

```bash
pip install -e ".[dev]"
pytest
python scripts/run_safety_eval.py
docker compose up --build
```

## Results

- Tests: pass/fail
- Benchmark: matched X/Y
- Docker demo: pass/fail
- Notes:

## Reproduction issues

- Issue 1:
- Issue 2:

## Interpretation

The current artifact is / is not reproducible for the documented benchmark and demo path.

## Non-claims

This validation does not prove production safety, compliance, or complete coverage.
```

## What counts as strong validation

Strong validation evidence includes:

- validator used a clean environment;
- commit SHA is recorded;
- commands are listed;
- benchmark output is included;
- failures are reported honestly;
- limitations are stated;
- no unsupported safety/compliance claims are made.

## Tracking validation results

Recommended tracking paths:

```text
docs/evidence/external_validation/
```

Possible files:

```text
docs/evidence/external_validation/2026-XX-XX-validator-handle.md
```

Each validation note should be small, factual, and reproducible.

## Success threshold for larger grants

For a $50k–$100k grant, a credible external-validation target is:

```text
At least 2 independent external validation notes
covering local install, tests, benchmark reproduction, and Docker demo reproduction.
```

A stronger target is:

```text
3–5 validators across QA, AI safety, and infra/security backgrounds.
```

## Bottom line

External validation should let a reviewer say:

```text
I did not build CML, but I could reproduce the documented tests,
benchmark result, and Docker demo from public instructions.
```

That is the evidence step that moves CML from an internal prototype toward a stronger grant-ready open-source research artifact.
