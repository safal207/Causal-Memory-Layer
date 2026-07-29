# CAEP interoperability reference demo

This directory demonstrates a portable CAEP record crossing three independent process boundaries:

```text
state server → action server → independent verifier
                      ↓
              CAEP execution bundle
```

The demo is **transport-neutral**. Each participant is a separate Python process exchanging JSON artifacts through files. This deliberately tests the portable record contract without claiming that the scripts implement the MCP wire protocol or an official MCP SDK.

## Scenarios

### Happy path

1. The state server observes an unpaid order.
2. The action server creates one payment.
3. The independent verifier reads the ledger.
4. A `verified` CAEP record is emitted.

### Recovery path

1. The state server observes an unpaid order.
2. A hidden parallel payment succeeds after the observation.
3. The action server creates a second payment using the stale observation.
4. The independent verifier detects two successful payments.
5. A `contained` CAEP divergence record is emitted.
6. The action server cancels the newest duplicate.
7. The verifier confirms exactly one successful payment.
8. A `recovered` CAEP record is emitted with a digest-bound reference to the divergent parent.

## Run

From this directory:

```bash
python run_demo.py --output /tmp/caep-interoperability-bundle.json
python -m unittest test_interoperability_demo.py
```

Expected summary:

```json
{"caep_validation":"valid","diverged":"diverged","happy":"verified","recovered":"verified"}
```

Before writing the bundle, the orchestrator loads the canonical parent-directory `caep.schema.json` and `validate_caep.py`. The happy record, divergent record, and recovered record with its exact parent must all validate successfully.

## Boundaries

- `filesystem-json` is a deterministic test transport, not the MCP protocol.
- The demo exercises cross-process record portability, causal parent binding, independent verification, critical postconditions, containment, and recovery.
- CAEP postcondition expressions remain declarations; this demo's verifier implements the concrete `successful_payment_count == 1` check.
- Record digests are computed over CAEP canonical bytes. Artifact digests are computed over deterministic JSON artifacts.
- A later adapter may replace the file transport with an official MCP SDK while keeping the CAEP bundle unchanged.

Disclosure: prepared with AI assistance under human direction and review.
