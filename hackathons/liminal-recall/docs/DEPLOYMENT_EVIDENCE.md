# Deployment and evidence protocol

## 1. Create CockroachDB memory layer

1. Create a CockroachDB Serverless cluster.
2. Create a SQL user dedicated to the demo.
3. Copy the connection string into a local environment variable named `DATABASE_URL`.
4. Apply the schema:

```bash
cockroach sql --url "$DATABASE_URL" --file schema.sql
```

5. Confirm the table exists:

```sql
SHOW TABLES;
SHOW CREATE TABLE agent_memories;
```

Capture screenshots without exposing the password or complete connection string.

## 2. Validate locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
python -m py_compile app/*.py
```

## 3. Deploy to AWS Lambda

```bash
sam build
sam deploy --guided \
  --parameter-overrides DatabaseUrl="$DATABASE_URL"
```

Record the stack name, AWS region, final commit SHA, and Function URL.

## 4. Runtime proof

Set:

```bash
BASE_URL="https://<lambda-function-url>"
```

Health:

```bash
curl -s "$BASE_URL/healthz"
```

Store a verified-negative outcome:

```bash
curl -s -X POST "$BASE_URL/memories" \
  -H 'content-type: application/json' \
  -d '{
    "session_id":"payments-agent",
    "kind":"outcome",
    "content":"Refund was sent twice after retry without idempotency key",
    "tags":["refund","payment","retry"],
    "status":"negative",
    "confidence":0.98
  }'
```

Save the returned outcome UUID as `OUTCOME_ID`.

Ask for a later decision:

```bash
curl -s -X POST "$BASE_URL/decisions" \
  -H 'content-type: application/json' \
  -d '{
    "session_id":"payments-agent",
    "proposed_action":"Retry the customer refund payment",
    "tags":["refund","payment","retry"]
  }'
```

Required proof markers:

```text
decision = HUMAN_REVIEW
memory_ids contains OUTCOME_ID
execution.status = NOT_EXECUTED
decision_memory_id is present
```

## 5. Persistence proof

Cause a fresh Lambda execution environment by redeploying the same code or updating a harmless environment variable. Do not delete the CockroachDB cluster or table.

Repeat the decision request. The response must still cite `OUTCOME_ID`. Then list the session:

```bash
curl -s "$BASE_URL/memories?session_id=payments-agent&limit=20"
```

Evidence must show both the original negative outcome and at least one later decision whose `parent_memory_id` equals `OUTCOME_ID`.

## 6. Evidence manifest

Record these values in the final submission package:

```text
repository_commit_sha:
aws_region:
cloudformation_stack:
lambda_function_url:
cockroach_cluster_region:
schema_applied_at:
negative_outcome_id:
decision_memory_id:
cloudwatch_log_stream:
demo_video_url:
```

## 7. Secret handling

Never publish:

- the complete `DATABASE_URL`;
- database passwords;
- AWS access keys;
- session tokens;
- screenshots containing reusable credentials.

The public demo may expose the Function URL, but the database credential must remain in encrypted Lambda configuration or AWS Secrets Manager.

## Claim boundary

A successful demo proves that the AWS-hosted application stored and recalled durable memory from CockroachDB and used that memory in a later advisory decision. It does not prove universal semantic matching, autonomous execution safety, or protection against every database or cloud failure mode.
