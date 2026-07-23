# Deployment and evidence protocol

This protocol separates implementation claims from live proof. Do not mark the submission ready until every required artifact is captured from the final commit and sanitized.

## 1. Create and identify the CockroachDB memory layer with ccloud

Authenticate with the CockroachDB Cloud organization that owns the demo cluster:

```bash
ccloud auth login
ccloud auth whoami
```

Create or select a CockroachDB Cloud cluster. For a new zero-spend Basic cluster, use the current `ccloud` command supported by your account and region, then set:

```bash
export COCKROACH_CLUSTER="<cluster-name-or-id>"
export DATABASE_URL="<sql-connection-string>"
```

Generate machine-readable, redacted ccloud evidence:

```bash
python scripts/ccloud_evidence.py \
  --cluster "$COCKROACH_CLUSTER" \
  --output evidence/ccloud-evidence.json
```

Required checks:

- the file was produced by live `ccloud ... -o json` commands;
- the cluster identity matches the deployment;
- secrets, connection strings, tokens, passwords, and certificates are redacted;
- the evidence timestamp is before the submission deadline and close to the final deployment.

This artifact proves meaningful use of the **ccloud CLI** as the agent-readable control-plane/evidence tool.

## 2. Apply and verify the distributed vector schema

Apply the schema to the live cluster:

```bash
cockroach sql --url "$DATABASE_URL" --file schema.sql
```

Confirm the table and vector index:

```sql
SHOW CREATE TABLE agent_memories;
SHOW INDEX FROM agent_memories;
```

Required markers:

```text
embedding VECTOR(256)
agent_memories_semantic_idx
vector_cosine_ops
```

After at least one embedded memory exists, capture a real plan for the same query shape used by the application:

```sql
EXPLAIN
SELECT id, embedding <=> '<QUERY_VECTOR>'::VECTOR AS semantic_distance
FROM agent_memories
WHERE session_id = 'payments-agent'
  AND kind = 'outcome'
  AND status = 'negative'
  AND embedding IS NOT NULL
ORDER BY embedding <=> '<QUERY_VECTOR>'::VECTOR
LIMIT 12;
```

The captured plan must show vector-search/index behavior rather than a claim inferred only from the schema. This is the live proof for **CockroachDB Distributed Vector Indexing**.

Do not publish the database password or complete connection string.

## 3. Validate the final commit locally

From `hackathons/liminal-recall`:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
python -m py_compile app/*.py scripts/*.py
```

Record:

```text
repository_commit_sha:
test_count:
test_result:
validation_timestamp_utc:
```

The unit suite must cover:

- persistence contract and causal parent validation;
- changed decision after negative memory;
- distributed-vector retrieval reporting;
- Bedrock embedding request/response validation;
- optional demo-key protection;
- fail-closed authority boundary.

## 4. Deploy to AWS Lambda and Bedrock

Confirm Titan Text Embeddings V2 access in the chosen AWS region, then deploy:

```bash
sam build
sam deploy --guided \
  --parameter-overrides \
    DatabaseUrl="$DATABASE_URL" \
    DemoApiKey="$DEMO_API_KEY" \
    EmbeddingModelId="amazon.titan-embed-text-v2:0" \
    EmbeddingDimensions=256 \
    SimilarityThreshold=0.35
```

Record:

```text
aws_region:
cloudformation_stack:
lambda_function_name:
lambda_function_url:
embedding_model_id:
embedding_dimensions:
similarity_threshold:
repository_commit_sha:
```

Capture the final Lambda configuration or CloudFormation output without exposing environment values.

## 5. Live health and authorization proof

Set:

```bash
export BASE_URL="https://<lambda-function-url>"
```

Health remains public:

```bash
curl -s "$BASE_URL/healthz" | tee evidence/health-before.json
```

Required markers:

```text
status = ok
database_configured = true
semantic_recall_configured = true
embedding_model = amazon.titan-embed-text-v2:0
embedding_dimensions = 256
runtime_instance_id is present
```

When `DEMO_API_KEY` is configured, prove that a non-health request without the key receives `401`, then repeat it with `x-demo-key` and receive a normal application response. Never put the key in screenshots, repository files, shell history shared publicly, or video overlays.

## 6. Store a verified-negative outcome

```bash
curl -s -X POST "$BASE_URL/memories" \
  -H 'content-type: application/json' \
  -H "x-demo-key: $DEMO_API_KEY" \
  -d '{
    "session_id":"payments-agent",
    "kind":"outcome",
    "content":"Refund was sent twice after retry without an idempotency key",
    "tags":["refund","payment","retry"],
    "status":"negative",
    "confidence":0.98
  }' | tee evidence/outcome.json
```

Save:

```text
OUTCOME_ID=<returned id>
RUNTIME_ID_1=<returned runtime_instance_id>
```

Verify in CockroachDB that the record has a non-null 256-dimensional embedding.

## 7. Prove semantic recall with different wording

Use a proposed action that is semantically related but not dependent on exact token overlap:

```bash
curl -s -X POST "$BASE_URL/decisions" \
  -H 'content-type: application/json' \
  -H "x-demo-key: $DEMO_API_KEY" \
  -d '{
    "session_id":"payments-agent",
    "proposed_action":"Send the customer reimbursement again",
    "tags":["customer","payout"]
  }' | tee evidence/decision-before-restart.json
```

Required markers:

```text
decision = HUMAN_REVIEW
memory_ids contains OUTCOME_ID
retrieval.mode = cockroachdb_vector_cosine
retrieval.tool = distributed_vector_index
execution.status = NOT_EXECUTED
execution.authority = advisory_only
decision_memory_id is present
```

Query the stored decision and confirm `parent_memory_id = OUTCOME_ID`.

## 8. Prove memory survives process replacement

Force a fresh Lambda execution environment without changing or clearing CockroachDB. One bounded method is to update the Lambda description and wait for the configuration update:

```bash
aws lambda update-function-configuration \
  --function-name "$LAMBDA_FUNCTION_NAME" \
  --description "restart-proof-$(date -u +%Y%m%dT%H%M%SZ)"

aws lambda wait function-updated \
  --function-name "$LAMBDA_FUNCTION_NAME"
```

Call health until the runtime ID changes:

```bash
curl -s "$BASE_URL/healthz" | tee evidence/health-after.json
```

Save:

```text
RUNTIME_ID_2=<new runtime_instance_id>
```

Pass condition: `RUNTIME_ID_2 != RUNTIME_ID_1`.

Repeat the semantically related decision request and save it as `evidence/decision-after-restart.json`.

Pass conditions:

- the new response still cites `OUTCOME_ID`;
- retrieval remains `cockroachdb_vector_cosine`;
- decision remains `HUMAN_REVIEW`;
- the runtime ID differs from the first request;
- the database memory ID remains unchanged.

The runtime-ID change proves process replacement. The stable outcome UUID proves CockroachDB durability.

## 9. Observability proof

Capture sanitized CloudWatch/X-Ray evidence for:

- one memory write;
- one Bedrock embedding call;
- one vector recall decision;
- one request after process replacement;
- no secret values in logs.

Record the CloudWatch log stream or trace identifiers in the evidence manifest. Avoid claiming end-to-end traces unless the final artifacts actually show them.

## 10. Final evidence manifest

Record these values in a single final manifest:

```text
repository_commit_sha:
repository_url:
license_visible_at_repository_root:
aws_region:
cloudformation_stack:
lambda_function_name:
lambda_function_url:
cockroach_cluster_name_or_id:
cockroach_cluster_region:
ccloud_evidence_path:
vector_index_name:
vector_explain_evidence_path:
schema_applied_at_utc:
embedding_model_id:
negative_outcome_id:
first_decision_memory_id:
runtime_instance_id_before:
runtime_instance_id_after:
cloudwatch_log_stream_or_trace:
demo_video_url:
devpost_submission_url:
judging_availability_end: 2026-09-15T17:00:00-04:00
```

## 11. Video proof order — target 2:35

1. **0:00–0:18:** costly failure: an agent repeats a refund after losing prior outcome context.
2. **0:18–0:35:** architecture: Lambda + Bedrock + CockroachDB vector memory + ccloud evidence.
3. **0:35–1:00:** store the verified-negative outcome and show its UUID/embedding record.
4. **1:00–1:28:** use different wording; show vector recall, `HUMAN_REVIEW`, exact UUID, and causal decision link.
5. **1:28–1:50:** show vector index/plan and redacted ccloud JSON evidence.
6. **1:50–2:15:** replace Lambda runtime; show changed runtime ID and unchanged memory UUID.
7. **2:15–2:35:** close on the product value and advisory authority boundary.

Judges are not required to watch beyond three minutes. Do not include copyrighted music, third-party trademarks without permission, or credentials.

## 12. Secret and claim handling

Never publish:

- complete `DATABASE_URL` values;
- database passwords;
- AWS access keys or session tokens;
- CockroachDB API keys;
- demo API keys;
- reusable certificates or private endpoints containing credentials.

A successful demo proves that the AWS-hosted application uses Bedrock embeddings and CockroachDB vector memory to recall a durable verified outcome after process replacement and influence a later advisory decision. It does not prove universal semantic correctness, autonomous execution safety, or immunity to every cloud/database failure mode.
