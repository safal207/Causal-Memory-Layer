# CML SAST / Security Review Report — 2026-04-24

## Date
- 2026-04-24 (UTC)

## Scope
Repository: `safal207/Causal-Memory-Layer`

Reviewed components:
- Core SDK and causal model: `cml/`
- CLI: `cli/`
- API server/store: `api/`
- Security-relevant docs and examples: `examples/`, `demos/`, `benchmarks/`
- Tests: `tests/`

## Repository structure discovery
- Main source directories: `cml/`, `cli/`, `api/`, `integrations/vscode-cml/`, `vcml/`
- CLI entry point(s): `cli/main.py` (`cml` script via `pyproject.toml`)
- Test directories: `tests/`
- Demo/example directories: `demos/`, `examples/`, `benchmarks/fixtures/`
- Existing audit/validation logic:
  - `cml/audit.py` (R1–R4 + custom rules)
  - `cli/audit.py` (CLI-side rule implementation)
  - `cml/record.py` JSONL record parsing
  - `cml/chain.py` lineage reconstruction

## Method
1. Ran environment/tooling checks.
2. Attempted Bandit and Semgrep scans.
3. Ran targeted `rg` pattern searches for risky APIs and secrets.
4. Ran unit tests.
5. Performed manual review of causal-integrity-critical logic and CLI behavior.
6. Implemented minimal high-confidence fail-closed hardening changes.
7. Added regression tests.

## Commands attempted / verification path
```bash
python3 --version
pipx --version || true
semgrep --version || true
bandit --version || true

pipx run --spec bandit bandit -r . -f txt || true
pipx run --spec semgrep semgrep --config auto --error --metrics=off --json . || true

rg -n "subprocess\.|os\.system|pickle\.loads|yaml\.load\(|eval\(|exec\(|md5|sha1|random\.random\(|secrets\.token|uuid\.uuid4" .
rg -n "(AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----|secret[_-]?key\s*[:=]\s*['\"][^'\"]{8,}|password\s*[:=]\s*['\"][^'\"]{6,}|token\s*[:=]\s*['\"][^'\"]{8,})" --glob '!**/fixtures/**' --glob '!**/test*' .
pytest -q || true
```

## Tooling availability and limitations
- `python3`: available.
- `pipx`: available.
- `semgrep`/`bandit` binaries: not preinstalled globally.
- `pipx run --spec bandit ...`: succeeded.
- `pipx run --spec semgrep --config auto --metrics=off ...`: failed due to Semgrep constraint (`auto` config requires metrics enabled).
- No claim is made for a full Semgrep run in this environment.

## Findings

### HIGH
- **None confirmed** by executed checks and manual review.

### MEDIUM
1. **Fail-open CLI parsing behavior (fixed)**
   - Prior CLI behavior skipped invalid JSON lines with warning and continued processing.
   - Risk: malformed logs could still produce valid-looking audit output.
   - Remediation: CLI now fails closed with explicit parse error and exit code 1 for invalid JSON or malformed required fields, including strict integer checks (rejecting bool-as-int) and non-empty `parent_cause` when provided.

2. **Unknown custom severity handling ambiguity (fixed)**
   - Prior config accepted arbitrary severity strings for custom rules.
   - Risk: non-standard severity could evade summary accounting semantics.
   - Remediation: strict severity normalization/validation (`OK|WARN|FAIL`) with explicit `ValueError` on unknown values.

### LOW
1. Bandit produced numerous low-severity findings in tests (`assert` usage, subprocess in tests), expected for pytest-style test code.
2. Bandit false-positive hardcoded password string on enum numeric value in `cml/ctag.py`.

### INFO
- UUID usage is present for record IDs (`uuid.uuid4`) in runtime and monitor scripts.
- No `eval`, `exec`, `pickle.loads`, `os.system`, or unsafe `yaml.load` usage found in scanned paths.

## Positive observations
- Core config YAML parsing uses `yaml.safe_load`.
- Core API parsing path rejects invalid records with HTTP 422.
- Causal integrity rule set has deterministic decision codes (R1–R4).
- Existing tests already exercise core fail scenarios (missing parent, secret→net lineage failure).

## Risk summary
Current state is improved toward fail-closed behavior for ingestion and rule semantics. Remaining risk is mostly from incomplete static-analysis coverage (Semgrep auto-config path not completed in this run) and architectural duplication (`cli/audit.py` separate from SDK audit engine), which may drift over time.

## Remediation plan
1. Keep fail-closed CLI parsing and enforce schema checks on all JSONL lines. **[implemented]**
2. Keep strict severity normalization for custom rules. **[implemented]**
3. Consolidate CLI audit implementation onto `cml.audit` engine to remove duplicate semantics. **[planned]**
4. Add CI jobs for Bandit + Semgrep with pinned configs and reproducible output artifacts. **[planned]**

## Re-run checklist
- [x] `pytest -q`
- [x] CLI regression tests include bool-as-int rejection and empty `parent_cause` rejection
- [x] Bandit executed with `pipx run --spec bandit`
- [ ] Semgrep full run with stable explicit config (`p/ci` or project policy set) in CI
- [ ] Dependency vulnerability scan (e.g., `pip-audit`) in CI

## Follow-up status checklist
- [x] remediation implemented
- [ ] full re-run completed in network-enabled environment
- [ ] CI SAST pipeline added

## Invariant alignment
This review and patch set reinforces the CML invariant:

> **A system must not become unsafe silently.**

The main practical change is strict fail-closed handling for malformed CLI logs and unknown decision-severity states.
