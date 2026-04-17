# Expected outputs (reference)

## Audit (text)

Command:

```bash
python -m cli.main audit examples/secret_to_net_log.jsonl
```

Expected shape:

- Overall status: `FAILED`
- Finding count includes exactly one `FAIL`
- Fail code: `CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN`
- Failing record: `b3`

## Chain inspection for failing record

Command:

```bash
python -m cli.main chain examples/secret_to_net_log.jsonl b3
```

Expected shape:

- `has_gap: true`
- `chain` contains only `b3` (no valid parent traversal)
- `r3_context.secret_record.id` is `b2`
- context note indicates secret access exists but is not causally linked to `b3`

## Chain inspection for valid comparison record

Command:

```bash
python -m cli.main chain examples/secret_to_net_log.jsonl a5
```

Expected shape:

- `has_gap: false`
- chain includes `a5` and traces through secret-related ancestor records
- no R3-style missing-link context for the valid branch
