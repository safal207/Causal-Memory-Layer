# Ready for Review Checklist

Use this checklist before sharing the repository with grant reviewers, partners, or external contributors.

## Repository Baseline
- [ ] `README.md` has purpose, quickstart, and current project status.
- [ ] `LICENSE` is present and matches README claims.
- [ ] `.gitignore` covers build/cache/dependency artifacts.
- [ ] `SECURITY.md` exists with reporting instructions.
- [ ] CI runs on push and pull request for default branch.

## Quality Signals
- [ ] At least one reproducible validation command is documented.
- [ ] Tests and CI are aligned with claims in README.
- [ ] No placeholder/WIP scripts in reviewer-facing commands.
- [ ] Key badges are visible in README (CI, tests, security when available).

## Hygiene
- [ ] No tracked `target/`, `.pytest_cache/`, `node_modules/`, logs, or temp files.
- [ ] No committed secrets (`.env`, private keys, tokens, credentials dumps).
- [ ] Large generated artifacts are excluded from VCS unless explicitly needed.

## Final Gate
- [ ] Fresh clone passes documented quickstart.
- [ ] Fresh clone passes documented test/validate command.
- [ ] Latest CI is green on default branch.
