# Liminal Recall

**CockroachDB × AWS Hackathon — Build with Agentic Memory**

Liminal Recall is a causally auditable safety-memory service for AI agents. It stores observations, decisions, and verified outcomes in CockroachDB, uses Amazon Bedrock embeddings plus CockroachDB Distributed Vector Indexing to recall semantically related failures, and makes later actions safer after restarts, retries, and process replacement.

## What the demo proves

1. An agent stores a verified negative outcome such as a duplicate refund caused by a non-idempotent retry.
2. Amazon Bedrock generates a normalized embedding and CockroachDB persists it beside the transactional memory record.
3. A later action with different wording retrieves the earlier outcome through a cosine vector search.
4. The agent returns `HUMAN_REVIEW`, cites exact memory UUIDs, and persists a causally linked decision record.
5. A new Lambda runtime receives a different `runtime_instance_id` but recalls the same CockroachDB memory UUID.
6. The system remains advisory and always reports `execution.status = NOT_EXECUTED`.

## Required platform integrations

### CockroachDB tool 1 — Distributed Vector Indexing

`schema.sql` creates a 256-dimensional `VECTOR` column and a cosine vector index with exact prefix filters for `session_id`, `kind`, and `status`. Runtime decision requests use that index to find semantically relevant verified-negative outcomes.

### CockroachDB tool 2 — ccloud CLI

`scripts/ccloud_evidence.py` runs agent-readable `ccloud ... -o json` commands, captures cluster identity/state, redacts sensitive fields, and writes a reviewable evidence manifest. The final submission must attach evidence generated against the live cluster.

### AWS services

- **AWS Lambda** executes the remember, recall, decide, and persist workflow.
- **Amazon Bedrock Titan Text Embeddings V2** generates normalized vectors.
- **Lambda Function URL** provides the functional demo endpoint.
- **CloudWatch and X-Ray** provide execution evidence.

See [`docs/architecture.md`](docs/architecture.md) and [`docs/JUDGING_SCORECARD.md`](docs/JUDGING_SCORECARD.md).

## Endpoints

- `GET /healthz`
- `POST /memories`
- `GET /memories?session_id=<id>&limit=20`
- `POST /decisions`

All responses include `runtime_instance_id`. When `DEMO_API_KEY` is configured, non-health routes require the `x-demo-key` header.

### Store a negative outcome

```bash
curl -X POST "$BASE_URL/memories" \
  -H 'content-type: application/json' \
  -H "x-demo-key: $DEMO_API_KEY" \
  -d '{
    "session_id": "checkout-agent",
    "kind": "outcome",
    "content": "Refund was sent twice after retry without an idempotency key",
    "tags": ["refund", "payment", "retry"],
    "status": "negative",
    "confidence": 0.98
  }'
```

### Ask for a semantically related decision

```bash
curl -X POST "$BASE_URL/decisions" \
  -H 'content-type: application/json' \
  -H "x-demo-key: $DEMO_API_KEY" \
  -d '{
    "session_id": "checkout-agent",
    "proposed_action": "Send the customer reimbursement again",
    "tags": ["customer", "payout"]
  }'
```

Expected markers:

```json
{
  "decision": "HUMAN_REVIEW",
  "memory_ids": ["<stable-outcome-uuid>"],
  "retrieval": {
    "mode": "cockroachdb_vector_cosine",
    "memory_layer": "cockroachdb",
    "tool": "distributed_vector_index"
  },
  "execution": {
    "status": "NOT_EXECUTED",
    "authority": "advisory_only"
  },
  "runtime_instance_id": "<lambda-runtime-uuid>"
}
```

## Local validation

```bash
cd hackathons/liminal-recall
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
python -m py_compile app/*.py scripts/*.py
```

The root protected CI also imports this application and verifies both the causal decision contract and semantic/Titan integration contract. Live CockroachDB, Bedrock, and Lambda behavior must still be proven separately with the deployment evidence protocol.

## CockroachDB setup

Create or select a CockroachDB Cloud cluster, obtain a SQL connection string, and apply the schema:

```bash
cockroach sql --url "$DATABASE_URL" --file schema.sql
```

Verify the vector index and query plan:

```sql
SHOW INDEX FROM agent_memories;

EXPLAIN
SELECT id
FROM agent_memories
WHERE session_id = 'checkout-agent'
  AND kind = 'outcome'
  AND status = 'negative'
  AND embedding IS NOT NULL
ORDER BY embedding <=> '[<256-dimensional-query-vector>]'::VECTOR
LIMIT 3;
```

Capture output showing the vector index/search without exposing credentials.

Generate ccloud evidence:

```bash
python scripts/ccloud_evidence.py \
  --cluster "$COCKROACH_CLUSTER" \
  --output evidence/ccloud-evidence.json
```

Review the generated JSON before committing or attaching it.

## AWS deployment

The SAM template grants the Lambda function least-purpose permissions to invoke the configured Bedrock embedding model, write logs/traces, and exposes a bounded public demo with reserved concurrency.

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

For a longer-lived deployment, move `DATABASE_URL` and the demo key to AWS Secrets Manager rather than treating encrypted Lambda environment variables as the final production design.

## Restart-persistence proof

1. Store the negative outcome and save its UUID plus the first `runtime_instance_id`.
2. Call `/decisions` and confirm vector recall, `HUMAN_REVIEW`, and the exact outcome UUID.
3. Force a fresh Lambda execution environment by updating a harmless configuration field or redeploying the same code.
4. Repeat `/healthz` until `runtime_instance_id` changes.
5. Repeat `/decisions` and confirm the earlier outcome UUID is still cited.
6. Query `/memories` and confirm the decision record has `parent_memory_id` equal to the outcome UUID.

The changed runtime ID proves process replacement. The unchanged memory UUID proves CockroachDB durability.

## Safety and product-readiness boundaries

- Retrieval influences a recommendation but never authorizes execution.
- Database or Bedrock failure returns a fail-closed `HUMAN_REVIEW` response.
- Optional constant-time API-key comparison protects demo routes.
- Session, memory type, status, cosine threshold, and a bounded result count constrain recall.
- Public evidence must redact connection strings, passwords, tokens, certificates, and AWS credentials.
- The project does not claim that semantic similarity alone proves causality; the causal link records which memory influenced the stored decision.

## New-project and reuse disclosure

Liminal Recall was created during the hackathon submission period inside the pre-existing Causal Memory Layer repository for development convenience. The AWS Lambda application, CockroachDB vector schema, Bedrock embedding integration, persistent-memory workflow, ccloud evidence runbook, deployment assets, and demo scenario are new for this submission. The final Devpost entry must identify any reused pre-existing source precisely.

## Current claim boundary

The repository now contains the implementation and evidence protocol for the two required CockroachDB tools and AWS deployment. It does **not** claim that live deployment evidence exists until the following are attached to the final commit/submission:

- live CockroachDB vector-index proof;
- redacted ccloud evidence generated from the live cluster;
- public AWS Function URL and valid testing credentials if enabled;
- restart-persistence proof with two different runtime IDs;
- public video under three minutes;
- final screenshots, URLs, license visibility, and Devpost fields.
