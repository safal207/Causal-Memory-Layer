# PyPI Pre-release Blockers — 2026-06-06

This note captures packaging risks found before publishing `causal-memory-layer` version `0.4.0`.

## Current target

- Package name: `causal-memory-layer`
- Version: `0.4.0`
- Source of truth: `pyproject.toml`
- Release issue: #31

## Status

Do not publish to PyPI until these items are checked or explicitly deferred.

## Blocker 1 — Package validation evidence on current `main`

The current `main` commit should have either:

- a successful `Python Package Validation` workflow run, or
- equivalent local validation evidence posted to #31.

Expected validation sequence:

```bash
python -m pip install --upgrade pip build twine
pip install -e ".[dev]"
pytest
python scripts/run_safety_eval.py
python -m build
python -m twine check dist/*
python -m venv .venv-wheel
. .venv-wheel/bin/activate
python -m pip install --upgrade pip
pip install dist/*.whl
cml --help
python - <<'PY'
import cml
print("cml import ok")
PY
```

## Blocker 2 — MCP entry point / optional dependency behavior

`pyproject.toml` exposes both console scripts:

```toml
[project.scripts]
cml = "cli.main:main"
cml-mcp = "cml.integrations.mcp.server:main"
```

But `mcp` is currently an optional dependency under `[project.optional-dependencies].mcp`.

Before release, decide and document one of these paths:

1. Keep `cml-mcp` as an installed entry point and document that users must install with:

```bash
pip install "causal-memory-layer[mcp]"
```

2. Move MCP server startup behind a clearer optional-extra guard with a helpful error message.

3. Remove or defer the `cml-mcp` entry point until the MCP packaging path is validated.

## Blocker 3 — MCP core imports helper from `scripts/`

Current MCP core imports:

```python
from scripts.run_experimental_cause_band_eval import extract_fixture_payload
```

The package discovery config currently includes:

```toml
[tool.setuptools.packages.find]
include = ["cml*", "cli*", "api*"]
```

That means `scripts/` is not part of the installed wheel package surface.

Risk:

- editable installs may work because the repository root is on the path;
- wheel installs may fail when importing `cml.integrations.mcp.core` or running `cml-mcp`.

Recommended fix:

- Move `extract_fixture_payload` into a package module, for example:

```text
cml/experimental/cause_band_payload.py
```

or directly into:

```text
cml/experimental/cause_band.py
```

Then update both:

```text
scripts/run_experimental_cause_band_eval.py
cml/integrations/mcp/core.py
```

to import from the packaged `cml.*` module.

## Suggested extra validation before PyPI

After the standard wheel validation, also run:

```bash
python -m venv .venv-mcp-wheel
. .venv-mcp-wheel/bin/activate
python -m pip install --upgrade pip
pip install "dist/*.whl[mcp]"
cml-mcp --help || true
python - <<'PY'
from cml.integrations.mcp import core
print(core.health())
PY
```

If `cml-mcp` is not expected to support `--help`, replace that command with a minimal import/startup smoke test that does not hang in CI.

## Release rule

A PyPI release should not imply production safety, compliance certification, enforcement behavior, or stable Cause Band semantics.

It should only mean:

> the package can be built, checked, installed from a wheel, imported, and invoked reproducibly.
