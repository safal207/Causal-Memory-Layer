# Start Here — Contributing to CML

Causal Memory Layer (CML) is an open-source causal audit layer for checking whether sensitive actions are grounded in a valid chain of permission, intent, and responsibility.

The core invariant is simple:

> A system may be functionally correct while being causally invalid.

CML exists to make that difference inspectable.

## 10-minute onboarding path

1. Read the root `README.md` to understand the problem and the current artifact.
2. Read `ROADMAP.md` to see how CML evolved from semantics to vCML, CTAG, multi-boundary memory, hypervisor semantics, hardware mapping, and monetization/distribution.
3. Read `CONTRIBUTING.md` for contribution expectations.
4. Run the fast validation flow:

```bash
pip install -e ".[dev]"
pytest
```

5. Run the deterministic safety benchmark:

```bash
python scripts/run_safety_eval.py
```

6. Review beginner-friendly issues labeled `good first issue` or `help wanted`.

## What CML is

CML validates causal lineage. It asks whether an action that happened was properly grounded in prior authorization, intent, and responsibility.

It is useful when ordinary logs can tell you what happened but cannot tell you whether what happened was causally permitted.

Examples of failures CML is designed to surface:

- a sensitive action with no valid parent cause,
- malformed or ambiguous root authority,
- secret access followed by network egress without valid causal linkage,
- responsibility lost across handoffs,
- plausible model output built on the wrong causal path.

## Main concepts

- **Causal record** — a structured event with cause, effect, authority, and responsibility context.
- **Causal chain** — linked records showing how an action was grounded.
- **vCML** — concrete record/format semantics for representing causal memory in systems.
- **CTAG** — compact causal tags for domain/class/generation/local hint/seal semantics.
- **Audit rule** — a deterministic check over causal lineage.
- **Finding** — an audit result such as missing parent, malformed root, unmarked gap, or secret-to-network lineage failure.
- **Benchmark fixture** — reproducible example used to verify expected audit behavior.

## Safe contribution zones

These are good places for new contributors:

- Documentation improvements.
- Quickstart validation on a clean machine.
- Example logs and walkthroughs.
- Benchmark evidence summaries.
- CLI help text improvements.
- API contract documentation.
- PyPI release checklist work.
- Compliance pack roadmap documentation.
- Tests that preserve existing semantics.

## Changes that need deeper review

These areas should be discussed before implementation:

- CML/vCML semantic changes.
- New audit rule meanings.
- CTAG encoding changes.
- Claims about compliance, certification, or security guarantees.
- Hypervisor/hardware semantics.
- Changes that alter expected benchmark outcomes.
- Breaking package or CLI behavior.

## Recommended first issues

Good starting points:

1. Verify the README quickstart on a clean machine.
2. Improve a confusing example or walkthrough.
3. Add a benchmark evidence snapshot for reviewers.
4. Prepare PyPI release checklist documentation.
5. Draft a Hosted Audit API MVP contract.

## Local validation

Use a fresh virtual environment when possible:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
pytest
python scripts/run_safety_eval.py
```

On Windows PowerShell, activation is usually:

```powershell
.venv\Scripts\Activate.ps1
```

## Repository map

- `cml/` — core Python causal validation and audit implementation.
- `cli/` — command-line interface.
- `api/` — API and store layer.
- `vcml/` — vCML semantics, format, CTAG, Linux/eBPF, hypervisor, and hardware docs.
- `examples/` — sample logs, reports, and causal mismatch walkthroughs.
- `benchmarks/` — deterministic benchmark fixtures and results.
- `tests/` — regression tests.
- `docs/` — supporting docs for review, SDK, enterprise, and scenarios.

## Research and product boundary

CML is one validation primitive, not a full safety stack. It does not execute policy by itself and does not claim to solve all AI safety, security, or compliance problems.

Its practical value is narrower and stronger:

> CML checks whether recorded sensitive actions preserve valid causal lineage.

That makes it useful for agentic oversight, security auditing, fintech controls, compliance review, and research on causal validity in AI workflows.

## Contribution principle

A strong CML contribution should preserve three things:

1. **Causal clarity** — the meaning of authority, intent, and responsibility must stay explicit.
2. **Reproducibility** — examples and findings should be testable.
3. **No overclaiming** — CML should state what it checks and what it does not check.
