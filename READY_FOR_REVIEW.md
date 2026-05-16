# Ready for Review Checklist

Use this checklist before sharing the repository with grant reviewers, partners, or external contributors.

## Repository Baseline
- [x] `README.md` has purpose, quickstart, and current project status.
- [x] `LICENSE` is present and matches README claims.
- [x] `.gitignore` covers build/cache/dependency artifacts (`__pycache__/`, `dist/`, `build/`, `.coverage*`, `htmlcov/`, `.venv/`, `.env*`).
- [x] `SECURITY.md` exists with reporting instructions.
- [x] CI runs on push and pull request for default branch (`.github/workflows/ci.yml`).

## Quality Signals
- [x] At least one reproducible validation command is documented (`pytest` in README).
- [x] Tests and CI are aligned with claims in README.
- [x] No placeholder/WIP scripts in reviewer-facing commands.
- [x] Key badges visible in README (CI status, package validation, license, safety eval).

## Hygiene
- [x] No tracked `target/`, `.pytest_cache/`, `node_modules/`, logs, or temp files.
- [x] No committed secrets (`.env`, private keys, tokens). The strings `secret`/`key`/`token` only appear in demo fixtures describing the SECRET→NET audit scenario.
- [x] No large generated artifacts in VCS.

## Final Gate
- [x] Fresh clone passes documented quickstart (`pip install -e ".[dev]" && pytest` → 102 passed, 2 skipped).
- [x] Fresh clone passes documented test/validate command.
- [ ] Latest CI is green on default branch (verify after this PR merges).
