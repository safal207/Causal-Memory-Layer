# Trusted Publishing Setup — TestPyPI / PyPI

This guide captures the safe publication path for `causal-memory-layer` version `0.4.0`.

## Current release status

- Package name: `causal-memory-layer`
- Version: `0.4.0`
- Repository: `safal207/Causal-Memory-Layer`
- Publish workflow file: `.github/workflows/publish-python-package.yml`
- Release notes draft: `docs/release/RELEASE_NOTES_0.4.0.md`
- Package validation evidence: https://github.com/safal207/Causal-Memory-Layer/actions/runs/27063042787/job/79879380002

## Safety rule

Publish to TestPyPI first.

Do not publish to production PyPI until the TestPyPI upload and clean install smoke test have passed.

## TestPyPI Trusted Publisher settings

In TestPyPI, create or confirm a pending publisher for:

```text
Project name: causal-memory-layer
Owner: safal207
Repository name: Causal-Memory-Layer
Workflow filename: publish-python-package.yml
Environment: testpypi
```

Notes:

- `publish-python-package.yml` is the key workflow filename for the trusted publishing binding.
- The workflow display name `Publish Python Package` is useful for the GitHub UI but should not be treated as the primary binding field.
- The GitHub environment `testpypi` should exist before running the workflow.

## GitHub environment setup for TestPyPI

In GitHub repository settings:

```text
Settings > Environments > New environment
```

Create:

```text
testpypi
```

Recommended policy:

- allow deployment from `main`,
- keep production PyPI separate from TestPyPI,
- do not store PyPI upload tokens in repository secrets for this trusted publishing flow.

## Run TestPyPI publishing workflow

In GitHub:

```text
Actions > Publish Python Package > Run workflow
```

Use:

```text
Branch: main
Target: testpypi
```

Wait for these jobs to pass:

- Build and validate distributions
- Publish distributions to TestPyPI

## Test install from TestPyPI

Use a clean environment:

```bash
python -m venv .venv-testpypi
. .venv-testpypi/bin/activate
python -m pip install --upgrade pip
```

Preferred install command:

```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple causal-memory-layer==0.4.0
```

Why not only `--no-deps`?

```text
--no-deps can confirm that the package artifact is downloadable, but it can hide dependency-resolution issues.
```

A `--no-deps` check can be used as an additional artifact-only check, but the primary smoke test should allow normal dependency resolution via regular PyPI fallback.

Then run:

```bash
cml --help
python - <<'PY'
import cml
from cml.integrations.mcp import core
print("cml import ok")
print(core.health())
PY
```

Expected result:

- package installs,
- `cml --help` works,
- `import cml` works,
- MCP core import works without installing `[mcp]`,
- `core.health()` prints MCP integration status.

## Optional MCP extra check from TestPyPI

Only if TestPyPI dependency resolution works for all dependencies:

```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple "causal-memory-layer[mcp]==0.4.0"
```

Then run:

```bash
python - <<'PY'
from cml.integrations.mcp import core
print(core.health())
PY
```

Do not start long-running MCP server processes in smoke tests unless the process is explicitly bounded.

## Production PyPI Trusted Publisher settings

After TestPyPI succeeds, configure production PyPI with:

```text
Project name: causal-memory-layer
Owner: safal207
Repository name: Causal-Memory-Layer
Workflow filename: publish-python-package.yml
Environment: pypi
```

## GitHub environment setup for production PyPI

Create GitHub environment:

```text
pypi
```

Recommended production protection:

- require manual approval before deployment,
- restrict deployment to `main` or release-based process,
- keep production publishing separate from TestPyPI,
- do not publish production PyPI from casual workflow runs.

## Production publish

Only after TestPyPI succeeds and release notes are final.

Preferred path:

1. Create a GitHub Release for `0.4.0` using `docs/release/RELEASE_NOTES_0.4.0.md`.
2. Let the release event trigger the PyPI publish job.
3. Approve the `pypi` environment deployment if approval is configured.

Manual fallback:

```text
Actions > Publish Python Package > Run workflow
Target: pypi
```

Use the manual fallback only with explicit release approval.

## Verify production PyPI install

Use a clean environment:

```bash
python -m venv .venv-pypi
. .venv-pypi/bin/activate
python -m pip install --upgrade pip
pip install causal-memory-layer==0.4.0
cml --help
python - <<'PY'
import cml
print("cml import ok")
PY
```

## Non-claims

Publishing the package does not prove:

- production AI safety,
- regulatory compliance,
- runtime enforcement,
- stable Cause Band semantics,
- complete AI safety coverage,
- complete security coverage.

The correct claim is:

```text
The package can be built, checked, installed, imported, and invoked reproducibly as a causal-validity audit prototype for structured action traces.
```

## Evidence to post back to release issues

After TestPyPI:

- TestPyPI workflow run link,
- clean install command used,
- `cml --help` result,
- import smoke-test result.

After production PyPI:

- PyPI workflow run link,
- PyPI project URL,
- clean install command used,
- `cml --help` result,
- GitHub Release URL.

Update:

- #31
- #126
