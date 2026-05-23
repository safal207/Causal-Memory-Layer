# External Validation Notes

This directory collects independent reproduction notes for Causal Memory Layer.

Goal:

```text
Show that people outside the maintainer loop can run CML and reproduce the documented test, benchmark, and Docker demo path.
```

## Current target

```text
2-5 independent validation notes
```

## How to contribute

See issue:

```text
#77 external validation: reproduce CML benchmark and Docker walkthrough
```

Suggested validation note path:

```text
docs/evidence/external_validation/<YYYY-MM-DD>-<github-handle>.md
```

## What a good note records

- OS
- Python version
- Docker version
- repository commit SHA
- `pytest` result
- `python scripts/run_safety_eval.py` result
- Docker walkthrough result
- any confusion or reproduction problem

## Non-claims

An external validation note does not prove production safety, compliance, or complete coverage.

It only records whether the documented artifact could be reproduced in a specific environment.
