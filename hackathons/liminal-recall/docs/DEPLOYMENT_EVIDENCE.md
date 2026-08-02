# Deployment and evidence protocol

This protocol separates implementation claims from live proof. Do not mark the submission ready until every required artifact is captured from one exact final commit, sanitized, and bound to that deployed build SHA.

## 1. Prepare the exact source state

From the repository root, require a clean worktree and record the reviewed head:

```bash
git status --short
git rev-parse HEAD
```

Pass conditions:

- `git status --short` is empty;
- the SHA is a full lowercase 40-character value;
- the same SHA will be passed to SAM as `BuildSha` and later returned by `/healthz`.

Any later commit creates a new state and requires redeployment plus fresh evidence.

## 2. Identify the CockroachDB memory layer with ccloud

Authenticate with the CockroachDB Cloud organization that owns the demo cluster:

```bash
ccloud auth login
ccloud auth whoami
```

Create or select a CockroachDB Cloud cluster, then set private values:

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

- the file was produced by live ccloud commands;
- the cluster identity matches the deployment;
- secrets, connection strings, tokens, passwords, and certificates are redacted;
- `ccloud-evidence.json.sha256` contains the exact digest and filename;
- the evidence timestamp is close to the final deployment.

The final gate recomputes the SHA-256 digest and rejects a malformed sidecar, a changed filename, or substituted bytes.

## 3. Apply and verify the distributed vector schema

Apply the schema:

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

The deployment template and embedder both allow only 256 dimensions. This prevents Bedrock from producing vectors that the schema cannot store.

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

The plan must show vector-search/index behavior rather than a claim inferred only from schema text. Never publish the database password or complete connection string.

## 4. Validate locally and in protected CI

From `hackathons/liminal-recall`:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
python -m py_compile app/*.py scripts/*.py
```

Protected repository tests must also pass. They cover causal decisions, semantic retrieval mode, Titan dimensions, authenticated routes, verified CockroachDB TLS, evidence containment, checksum integrity, and runtime build identity.

Record:

```text
repository_commit_sha:
focused_test_count:
focused_test_result:
protected_ci_result:
python_package_validation_result:
security_baseline_result:
validation_timestamp_utc:
```

## 5. Deploy to AWS Lambda and Bedrock

Set a required private demo key of at least 16 random characters:

```bash
export DEMO_API_KEY="<private-random-value>"
```

The recommended path is:

```bash
python scripts/live_deploy.py preflight
python scripts/live_deploy.py all
```

The runner refuses a missing key or dirty worktree, applies the schema, captures ccloud evidence, builds SAM, and deploys the exact current SHA.

Manual equivalent:

```bash
BUILD_SHA="$(git rev-parse HEAD)"
sam build
sam deploy --guided \
  --parameter-overrides \
    DatabaseUrl="$DATABASE_URL" \
    DemoApiKey="$DEMO_API_KEY" \
    BuildSha="$BUILD_SHA" \
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
embedding_dimensions: 256
similarity_threshold:
repository_commit_sha:
deployed_build_sha:
```

Capture the final Lambda configuration or CloudFormation output without exposing environment values.

## 6. Prove health, build identity, and authorization

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
build_sha = repository_commit_sha
database_configured = true
semantic_recall_configured = true
embedding_model = amazon.titan-embed-text-v2:0
embedding_dimensions = 256
runtime_instance_id is present
```

Fail if `build_sha` is missing, malformed, or different from the reviewed head.

Prove fail-closed authentication:

1. a non-health request without `x-demo-key` receives `401`;
2. the same request with the private key receives a normal application response.

Never put the key in screenshots, repository files, shared shell history, logs, or video overlays.

## 7. Store a verified-negative outcome

```bash
curl -s -X POST "$BASE_URL/memories" \
  -H 'content-type: application/json' \
  -H "x-demo-key: $DEMO_API_KEY" \
  -d '{
    "session_id":"payments-agent",
    "kind":"outcome",
    "content":"Refund was sent twice after retry without an idempotency key",
    "tags":["duplicate","payment","idempotency"],
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

## 8. Prove semantic recall with different input

The later request intentionally uses different wording and non-overlapping tags:

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

## 9. Prove memory survives process replacement

Force a fresh Lambda execution environment without changing or clearing CockroachDB:

```bash
aws lambda update-function-configuration \
  --function-name "$LAMBDA_FUNCTION_NAME" \
  --description "restart-proof-$(date -u +%Y%m%dT%H%M%SZ)"

aws lambda wait function-updated \
  --function-name "$LAMBDA_FUNCTION_NAME"
```

Poll health until the runtime ID changes:

```bash
curl -s "$BASE_URL/healthz" | tee evidence/health-after.json
```

Pass conditions:

- `runtime_instance_id_after != runtime_instance_id_before`;
- post-restart `build_sha` still equals the reviewed commit;
- the repeated semantic decision still cites `OUTCOME_ID`;
- retrieval remains `cockroachdb_vector_cosine`;
- decision remains `HUMAN_REVIEW`;
- the CockroachDB memory ID remains unchanged.

The runtime-ID change proves process replacement. The stable outcome UUID proves CockroachDB durability. The stable exact build SHA proves both observations came from the reviewed artifact.

## 10. Observability proof

Capture sanitized CloudWatch or X-Ray evidence for:

- one authenticated memory write;
- one Bedrock embedding call;
- one vector recall decision;
- one request after process replacement;
- no secret values in logs.

Avoid claiming end-to-end traces unless the final artifacts actually show them.

## 11. Final evidence manifest

Copy `final-submission.example.json` into the private evidence directory and record:

```text
repository_commit_sha:
deployed_build_sha:
repository_url pinned to repository_commit_sha:
license_url pinned to repository_commit_sha:
aws_region:
cloudformation_stack:
lambda_function_name:
lambda_function_url:
cockroach_cluster_name_or_id:
ccloud_evidence_path:
vector_explain_evidence_path:
negative_outcome_id:
decision_memory_id_after:
runtime_instance_id_before:
runtime_instance_id_after:
retrieval_mode: cockroachdb_vector_cosine
retrieval_tool: distributed_vector_index
execution_authority: advisory_only
video_url:
devpost_submission_url:
judging_availability_end: 2026-09-15T17:00:00-04:00
```

All referenced evidence files must resolve inside the manifest directory. Absolute paths, `..` escapes, and symlinks that resolve outside the directory are rejected.

Run the gate:

```bash
python scripts/submission_gate.py evidence/final-submission.json \
  --report evidence/submission-gate-report.json
```

The gate must return `PASS` on the exact submitted head.

## 12. Video proof order — target 2:35

1. **0:00–0:18:** costly failure: an agent repeats a refund after losing prior outcome context.
2. **0:18–0:35:** architecture: Lambda + Bedrock + CockroachDB vector memory + ccloud evidence + build identity.
3. **0:35–1:00:** store the verified-negative outcome and show its UUID/embedding record.
4. **1:00–1:28:** use different wording and tags; show vector recall, `HUMAN_REVIEW`, exact UUID, and causal link.
5. **1:28–1:50:** show vector index/plan and redacted ccloud JSON with matching checksum.
6. **1:50–2:15:** show submitted `build_sha`, replace the Lambda runtime, then show changed runtime ID, unchanged SHA, and unchanged memory UUID.
7. **2:15–2:35:** close on product value and the advisory authority boundary.

Judges are not required to watch beyond three minutes. Do not include credentials, copyrighted music, or unlicensed third-party assets.

## 13. Secret and claim handling

Never publish:

- complete `DATABASE_URL` values;
- database passwords;
- AWS access keys or session tokens;
- CockroachDB API keys;
- demo API keys;
- reusable certificates or private endpoints containing credentials.

A successful demo proves that the exact submitted AWS-hosted build uses Bedrock embeddings and CockroachDB vector memory to recall a durable verified outcome after process replacement and influence a later advisory decision. It does not prove universal semantic correctness, autonomous execution safety, or immunity to every cloud or database failure mode.
