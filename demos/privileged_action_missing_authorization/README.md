# Demo Package: Privileged action without valid parent authorization

This is the next narrow CML demo after the secret→network causal-invalidity package.

**Core claim:** a privileged action can appear successful at runtime while still being causally invalid, because the chain cannot prove valid parent authorization.

---

## Why this scenario matters

In production systems, privileged actions are often evaluated by endpoint state only (for example: file updated, permission change applied, operation returned `success`).

CML adds the accountability question:

- Was that privileged action causally descended from a valid authorization parent?

If the parent authorization record is missing from lineage, runtime success does not equal causal validity.

---

## Reused repository primitives

This demo intentionally reuses existing CML pieces without adding any new subsystem:

- **Example fixture style** under `examples/`
- **Audit flow** from `cli/main.py` (via `python -m cli.main audit ...`)
- **Chain inspection** from `cli/main.py` + `cli/chain.py`
- **Audit rule semantics** from `cml/audit.py` (R1 reference integrity)
- **Demo package structure** from `demos/secret_to_network_causal_invalid/`

Fixture used here:

- `examples/privileged_action_missing_authorization_log.jsonl`

---

## Exact commands to run

From repository root:

```bash
python -m cli.main audit examples/privileged_action_missing_authorization_log.jsonl
python -m cli.main audit examples/privileged_action_missing_authorization_log.jsonl --format json
python -m cli.main chain examples/privileged_action_missing_authorization_log.jsonl b2
python -m cli.main chain examples/privileged_action_missing_authorization_log.jsonl a3
```

---

## What happened vs why invalid

### Surface-level (functionally acceptable)

- Record `b2` represents a privileged write to `/etc/shadow`.
- The event payload itself says `"status": "success"`.
- At a purely runtime/event-output level, this can look acceptable.

### CML causal verdict

- Record **`b2`** fails with `CML-AUDIT-R1-MISSING_PARENT`.
- It claims authorization lineage through `parent_cause: "b2_authz_parent_missing"`.
- That parent record does not exist in the log.
- Therefore, valid parent authorization is not provable.

---

## Rule violation shown

- **Rule:** R1 (`CML-AUDIT-R1-MISSING_PARENT`)
- **Meaning:** every non-null `parent_cause` must resolve to a real record.
- **Violation here:** privileged action `b2` references an authorization parent that is absent.

---

## Why this matters (AI / security / fintech / enterprise controls)

For high-impact actions, controls need to verify lineage, not only outcomes.

- **AI agents:** an agent can complete a sensitive step, but if approval ancestry is missing, accountability is broken.
- **Security operations:** "change succeeded" is insufficient when parent authorization cannot be reconstructed.
- **Fintech / enterprise governance:** auditability of who/what authorized a privileged step is required for post-incident and compliance evidence.

CML keeps the claim narrow: this is an audit finding about causal validity, not runtime enforcement.

---

## One-paragraph external narrative

This demo shows a privileged write that appears successful in runtime terms, but CML still marks it causally invalid. The reason is simple and strict: the action references a parent authorization record that is not present, so the authorization lineage cannot be proven. CML does not block execution; it makes this accountability break visible during audit.
