# PyPI Release Checklist — `causal-memory-layer`

**Package name:** `causal-memory-layer`  
**Current package version:** `0.4.0`  
**Release status:** checklist / not yet published  
**Source of truth:** `pyproject.toml`

This checklist prepares CML for a PyPI release without overclaiming that the package is already published or production-certified.

## Goal

Verify that CML can be built, checked, installed from a wheel, and used through the `cml` command-line entry point.

## Pre-release assumptions

Before publishing, confirm:

- The package name is available or owned on PyPI.
- The intended version is final.
- The README renders correctly as the package long description.
- The license metadata is correct.
- The CLI entry point works after wheel installation.
- Tests and safety-eval benchmark pass from a clean environment.

## Local validation environment

Use a clean virtual environment:

```bash
python --version
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

## Step 1 — Install local dev package

```bash
pip install -e ".[dev]"
pytest
python scripts/run_safety_eval.py
```

Expected result:

- editable install succeeds,
- test suite passes,
- deterministic safety benchmark completes.

## Step 2 — Build source and wheel distributions

```bash
python -m pip install --upgrade build twine
rm -rf dist build *.egg-info
python -m build
```

Expected artifacts:

```text
dist/causal_memory_layer-<version>.tar.gz
dist/causal_memory_layer-<version>-py3-none-any.whl
```

## Step 3 — Validate package metadata

```bash
python -m twine check dist/*
```

Expected result:

```text
PASSED
```

If this fails, common causes include:

- README rendering issue,
- missing license metadata,
- invalid project URL metadata,
- malformed long description.

## Step 4 — Install from wheel in a fresh environment

Create a second clean environment or reset the current one:

```bash
deactivate || true
python -m venv .venv-wheel
source .venv-wheel/bin/activate
python -m pip install --upgrade pip
pip install dist/*.whl
```

On Windows PowerShell:

```powershell
deactivate
python -m venv .venv-wheel
.venv-wheel\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install dist/*.whl
```

## Step 5 — Verify CLI entry point

```bash
cml --help
```

Expected result:

- command exists,
- help text is printed,
- command exits successfully.

## Step 6 — Smoke-test import surface

```bash
python - <<'PY'
import cml
print("cml import ok")
PY
```

Expected result:

```text
cml import ok
```

## Step 7 — Optional TestPyPI dry run

Only do this with a configured TestPyPI token.

```bash
python -m twine upload --repository testpypi dist/*
```

Then test installation from TestPyPI in a clean environment:

```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple causal-memory-layer
cml --help
```

## Step 8 — Production PyPI release

Only publish after local validation and/or CI package validation succeeds.

```bash
python -m twine upload dist/*
```

After publication:

```bash
pip install causal-memory-layer
cml --help
```

## CI validation

Package validation should be checked by GitHub Actions before publication.

Expected CI flow:

```bash
python -m pip install --upgrade pip build twine
pip install -e ".[dev]"
pytest
python scripts/run_safety_eval.py
python -m build
python -m twine check dist/*
pip install dist/*.whl
cml --help
```

## Release blocker checklist

Do not publish if any of these are true:

- [ ] Tests fail.
- [ ] Safety-eval benchmark fails.
- [ ] `python -m build` fails.
- [ ] `twine check dist/*` fails.
- [ ] Wheel installation fails.
- [ ] `cml --help` fails after wheel installation.
- [ ] README makes claims that are not supported by current evidence.
- [ ] Version number is not intentional.
- [ ] License/commercial positioning is unclear.

## Manual release notes template

```markdown
## causal-memory-layer <version>

### Highlights
- ...

### Validation
- pytest: pass/fail
- safety-eval benchmark: pass/fail
- build: pass/fail
- twine check: pass/fail
- wheel install: pass/fail
- cml --help: pass/fail

### Known limitations
- ...
```

## Evidence principle

A PyPI release should mean:

> The package can be installed, tested, and invoked reproducibly.

It should not imply production certification, regulatory compliance, or complete safety coverage.
