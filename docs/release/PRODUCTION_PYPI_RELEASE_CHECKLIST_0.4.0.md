# Production PyPI Release Checklist — `causal-memory-layer` 0.4.0

This checklist covers the final production release path after the successful TestPyPI publication and smoke test.

## Current verified state

TestPyPI publication has passed.

Evidence:

```text
https://github.com/safal207/Causal-Memory-Layer/actions/runs/27069357386
```

Confirmed:

- build and validation job: success,
- TestPyPI publish job: success,
- production PyPI job: skipped,
- TestPyPI install smoke test: passed,
- `cml --help`: passed,
- `import cml`: passed,
- MCP core import: passed,
- `core.health()`: passed.

## Release target

```text
Package: causal-memory-layer
Version: 0.4.0
Git tag: v0.4.0
Release title: causal-memory-layer 0.4.0 — package-validation-ready CML prototype
```

## 1. Production PyPI trusted publisher setup

Configure production PyPI trusted publishing for:

```text
Project name: causal-memory-layer
Owner: safal207
Repository name: Causal-Memory-Layer
Workflow filename: publish-python-package.yml
Environment: pypi
```

Important:

- use production PyPI, not TestPyPI;
- use environment `pypi`, not `testpypi`;
- the key workflow binding is the filename `publish-python-package.yml`.

## 2. GitHub environment protection

Confirm GitHub environment exists:

```text
pypi
```

Recommended protection:

- require manual approval before production deployment,
- restrict deployment to `main` or the release process,
- do not allow accidental casual production publish runs.

## 3. Final release notes review

Use:

```text
docs/release/RELEASE_NOTES_0.4.0.md
```

Before creating the GitHub Release, confirm it includes:

- package summary,
- install instructions,
- TestPyPI validation evidence,
- known limitations,
- explicit non-claims,
- no production safety or compliance overclaim.

## 4. Create GitHub Release

Create a GitHub Release with:

```text
Tag: v0.4.0
Target: main
Title: causal-memory-layer 0.4.0 — package-validation-ready CML prototype
```

Use the release notes from:

```text
docs/release/RELEASE_NOTES_0.4.0.md
```

Expected workflow behavior:

- release publication triggers `Publish Python Package`,
- build job runs,
- production PyPI publish job runs,
- TestPyPI job is skipped.

## 5. Verify production PyPI upload

After the workflow succeeds, verify the project page:

```text
https://pypi.org/project/causal-memory-layer/0.4.0/
```

## 6. Production install smoke test

Use a clean environment:

```bash
python -m venv .venv-pypi
. .venv-pypi/bin/activate
python -m pip install --upgrade pip
pip install causal-memory-layer==0.4.0
cml --help
python - <<'PY'
import cml
from cml.integrations.mcp import core
print("cml import ok")
print(core.health())
PY
```

Expected:

- package installs from production PyPI,
- dependency resolution succeeds,
- `cml --help` works,
- `import cml` works,
- MCP core import works,
- `core.health()` works.

## 7. Post-release repository updates

After production PyPI passes:

- update README install section to include:

```bash
pip install causal-memory-layer
```

- add production PyPI evidence to #31 and #126;
- optionally close #126 if all publishing acceptance criteria are complete;
- announce only the narrow validated claim.

## Non-claims to preserve

The release does not prove:

- production AI safety,
- regulatory compliance,
- runtime enforcement,
- stable Cause Band semantics,
- complete AI safety coverage,
- complete security coverage.

Correct claim:

```text
CML 0.4.0 is a package-validated, installable causal-validity audit prototype for structured action traces.
```
