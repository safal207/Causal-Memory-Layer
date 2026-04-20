# Expected outputs (reference)

## Audit (text)

Command:

```bash
python -m cli.main audit examples/privileged_action_missing_authorization_log.jsonl
```

Expected shape:

- Overall status: `FAILED`
- Findings include exactly one `FAIL`
- Fail code: `CML-AUDIT-R1-MISSING_PARENT`
- Failing record: `b2`
- Failure message states parent reference does not exist in log

## Audit (json)

Command:

```bash
python -m cli.main audit examples/privileged_action_missing_authorization_log.jsonl --format json
```

Expected shape:

- `summary.fail` is `1`
- one finding where:
  - `record_id` = `b2`
  - `severity` = `FAIL`
  - `code` = `CML-AUDIT-R1-MISSING_PARENT`

## Chain inspection for failing record

Command:

```bash
python -m cli.main chain examples/privileged_action_missing_authorization_log.jsonl b2
```

Expected shape:

- `has_gap: true`
- `chain` contains only `b2`
- `gap_note` explains that parent reference `b2_authz_parent_missing` is missing from the log
- No claim that runtime failed: only lineage proof failed

## Chain inspection for valid comparison record

Command:

```bash
python -m cli.main chain examples/privileged_action_missing_authorization_log.jsonl a3
```

Expected shape:

- `has_gap: false`
- chain includes `a1 -> a2 -> a3`
- no missing-parent message
