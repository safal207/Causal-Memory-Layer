# Demo Package: Secret → Network without valid causal lineage

This is the recommended first CML demo.

**Core claim:** a workflow can be functionally correct while still being causally invalid.

CML does not block execution. It audits recorded causality and answers whether a sensitive action was justified by valid permission/intent/responsibility lineage.

---

## Why this scenario first

This scenario directly matches CML's threat-model fit:

- secret access occurs
- outbound network action occurs
- action may look operationally fine
- causal audit proves the action chain is invalid

It is already supported by repository artifacts:

- `examples/secret_to_net_log.jsonl`
- `examples/secret_to_net_explain.md`
- `cml/audit.py` and `cml/chain.py`
- `cli/main.py`

---

## Reused repository primitives

- **Audit engine**: `python -m cli.main audit ...`
- **Chain reconstruction**: `python -m cli.main chain ...`
- **Fixture log**: `examples/secret_to_net_log.jsonl`
- **Context explainer**: `examples/secret_to_net_explain.md`

No new subsystem is introduced.

---

## Run the demo

From repository root:

```bash
python -m cli.main audit examples/secret_to_net_log.jsonl
python -m cli.main audit examples/secret_to_net_log.jsonl --format json
python -m cli.main chain examples/secret_to_net_log.jsonl b3
python -m cli.main chain examples/secret_to_net_log.jsonl a5
```

Optional baseline (clean pass case):

```bash
python -m cli.main audit examples/exec_causal_log.jsonl
```

---

## What happened vs why invalid

### Surface-level (functionally acceptable)

- Secret was read.
- Network send occurred.
- Tooling/action flow appears to have worked.

### Causal verdict (CML)

- Record **`b3`** fails with `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN`.
- The network event is not causally linked to prior secret access in the same process.
- Therefore the network-relevant action is **causally invalid** even if output looks correct.

---

## Rule violation shown

- **Rule:** R3 (`CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN`)
- **Meaning:** if a process accessed `SECRET` data, a later `NET_OUT` must have a valid ancestor path to that secret access.
- **Failure in this demo:** `b3` has `parent_cause: null` / `unobserved_parent`, so lineage to `b2` is missing.

---

## Why this matters (AI/security/fintech)

In high-trust systems, "it succeeded" is not enough.

You need to know whether sensitive effects were causally authorized and responsibility-preserving. CML makes hidden invalidity inspectable after the fact, enabling oversight, incident analysis, and compliance narratives grounded in lineage rather than output alone.

---

## One-paragraph external narrative

This demo shows a workflow that looks acceptable on the surface: a process reads a secret and later performs a network send. CML adds a different question: was that network-relevant action causally justified by valid permission and responsibility lineage? In the failing branch, the action still occurred, but the chain is broken, so CML marks it causally invalid. The result is not just an event log of what happened, but an audit verdict on whether the action should be considered accountable and valid.
