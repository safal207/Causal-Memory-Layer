# Liminal Recall

**CockroachDB × AWS Hackathon — Build with Agentic Memory**

Liminal Recall is a causally auditable safety-memory service for AI agents. It stores observations, decisions, and verified outcomes in CockroachDB, uses Amazon Bedrock embeddings plus CockroachDB Distributed Vector Indexing to recall semantically related failures, and makes later actions safer after restarts, retries, and process replacement.

## What the demo proves

1. An agent stores a verified negative outcome such as a duplicate refund caused by a non-idempotent retry.
2. Amazon Bedrock generates a normalized 256-dimensional embedding and CockroachDB persists it beside the transactional memory record.
3. A later action with different wording and independent tags retrieves the earlier outcome through cosine vector search.
4. The agent returns `HUMAN_REVIEW`, cites exact memory UUIDs, and persists a causally linked decision record.
5. A new Lambda runtime receives a different `runtime_instance_id` but recalls the same CockroachDB memory UUID.
6. `/healthz` reports the deployed `build_sha`, and evidence capture rejects a runtime that does not match the reviewed Git head.
7. The system remains advisory and always reports `execution.status = NOT_EXECUTED`.

## Required platform integrations

### CockroachDB tool 1 — Distributed Vector Indexing

`schema.sql` creates a 256-dimensional `VECTOR` column and a cosine vector index with exact prefix filters for `session_id`, `kind`, and `status`. Runtime decision requests use that index to find semantically relevant verified-negative outcomes. The deployment contract allows only 256-dimensional embeddings so Bedrock output cannot diverge from the schema.

### CockroachDB tool 2 — ccloud CLI

`scripts/ccloud_evidence.py` runs agent-readable `ccloud ... -o json` commands, captures organization and cluster state, redacts sensitive keys and credential-like strings, and writes a reviewable evidence manifest plus SHA-256 sidecar. The submission gate recomputes the digest and verifies the sidecar filename before accepting the evidence.

### AWS services

- **AWS Lambda** executes the remember, recall, decide, and persist workflow.
- **Amazon Bedrock Titan Text Embeddings V2** generates normalized vectors.
- **Lambda Function URL** provides the functional demo endpoint.
- **CloudWatch and X-Ray** provide execution evidence.

See [`docs/architecture.md`](docs/architecture.md), [`docs/JUDGING_SCORECARD.md`](docs/JUDGING_SCORECARD.md), [`docs/DEPLOYMENT_EVIDENCE.md`](docs/DEPLOYMENT_EVIDENCE.md), and [`docs/CAUSAL_COMMIT_TRAJECTORY.md`](docs/CAUSAL_COMMIT_TRAJECTORY.md).

## Endpoints and authentication

- `GET /healthz` — public health, runtime, and build-identity proof;
- `POST /memories` — requires `x-demo-key`;
- `GET /memories?session_id=<id>&limit=20` — requires `x-demo-key`;
- `POST /decisions` — requires `x-demo-key`.

All responses include `runtime_instance_id`. Non-health routes fail closed when `DEMO_API_KEY` is absent, empty, or does not match. The SAM template requires a key of at least 16 characters, and the deployment runner refuses to deploy without it.

### Store a negative outcome

```bash
curl -X POST "$BASE_URL/memories" \
  -H 'content-type: application/json' \
  -H "x-demo-key: $DEMO_API_KEY" \
  -d '{
    "session_id": "checkout-agent",
    "kind": "outcome",
    "content": "Refund was sent twice after retry without an idempotency key",
    "tags": ["duplicate", "payment", "idempotency"],
    "status": "negative",
    "confidence": 0.98
  }'
```

### Ask with different wording

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

The outcome and decision inputs deliberately do not share tokens. A successful live proof therefore demonstrates semantic retrieval rather than a zero-distance match or deterministic token overlap.

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

## Validation layers

Focused validation:

```bash
cd hackathons/liminal-recall
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
python -m py_compile app/*.py scripts/*.py
```

Protected repository CI imports this application and verifies the causal decision contract, semantic vector-tool reporting, Titan embedding shape, TLS defaults, authentication, ccloud redaction, evidence containment, checksum integrity, deployment-SHA binding, and live-evidence gates. Green CI is evidence; the final live deployment must still be recaptured against the exact final head.

## Fastest live path

The bounded deployment runner performs preflight checks, applies the CockroachDB schema, captures redacted ccloud evidence, deploys the SAM stack, runs the semantic-memory scenario, replaces the Lambda runtime, and verifies that the same outcome UUID survives.

Prepare private environment values. `.env.local` is ignored by the repository:

```bash
cd hackathons/liminal-recall
cp .env.example .env.local
# Fill .env.local locally. Never paste real credentials into GitHub or chat.
set -a
. ./.env.local
set +a
```

Check accounts, required secrets, repository cleanliness, and local tooling without changing cloud infrastructure:

```bash
python scripts/live_deploy.py preflight
```

Run the complete deployment and proof flow:

```bash
python scripts/live_deploy.py all
```

The runner refuses a dirty worktree, embeds the exact current commit as `BuildSha`, and compares it with `/healthz` before and after Lambda replacement. Generated artifacts are written to `evidence/` and ignored by Git by default. Review each artifact manually before selecting any sanitized files for judging.

## CockroachDB setup

The runner applies the schema automatically. Manual equivalent:

```bash
cockroach sql --url "$DATABASE_URL" --file schema.sql
```

When a database URL omits `sslmode`, the store defaults to `verify-full` and uses the packaged CockroachDB root certificate. Explicit URL settings remain authoritative.

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

Capture output showing the vector-search plan without exposing credentials. CockroachDB uses the vector index only when every prefix column is constrained to a specific value, which is why the runtime query filters `session_id`, `kind`, and `status` exactly.

Generate ccloud evidence manually:

```bash
python scripts/ccloud_evidence.py \
  --cluster "$COCKROACH_CLUSTER" \
  --output evidence/ccloud-evidence.json
```

The script uses current `ccloud auth whoami`, `ccloud settings`, and `ccloud cluster info` commands with structured-output compatibility handling. Review the generated JSON before publishing it.

## AWS deployment

The SAM template grants the Lambda function least-purpose permission to invoke the configured Bedrock embedding model and write trace telemetry. The Function URL is public at the transport layer so judges can reach `/healthz`, but application-level authentication is mandatory for every memory and decision route.

The deployment runner uses `sam build` and a non-interactive `sam deploy` with CloudFormation parameter overrides. Manual guided deployment remains available, but it must provide `DatabaseUrl`, `DemoApiKey`, and the exact 40-character `BuildSha`:

```bash
sam build
sam deploy --guided
```

For a longer-lived deployment, move `DATABASE_URL` and the demo key to AWS Secrets Manager rather than treating encrypted Lambda environment variables as the final production design.

## Restart-persistence and build-identity proof

The runner performs these checks automatically:

1. Require a clean repository and record the exact Git head.
2. Deploy that SHA as the Lambda `BUILD_SHA` environment value.
3. Call `/healthz`; reject a missing, malformed, stale, or unrelated build SHA.
4. Store the negative outcome and save its UUID plus the first `runtime_instance_id`.
5. Call `/decisions` with a different phrase and independent tags; confirm vector recall, `HUMAN_REVIEW`, and the exact outcome UUID.
6. Update a harmless Lambda configuration field and wait for completion.
7. Poll `/healthz` until `runtime_instance_id` changes while `build_sha` remains identical.
8. Repeat `/decisions` and confirm the earlier outcome UUID is still cited.
9. Save a bounded manifest containing both runtime IDs, the stable memory UUID, repository SHA, deployed SHA, and advisory-only markers.

The changed runtime ID is evidence of process replacement. The unchanged memory UUID is evidence of CockroachDB durability. The unchanged `build_sha` shows that both responses reported the reviewed source commit configured at deployment; it is not a hash or attestation of the built artifact bytes or resolved dependency set.

## Final submission gate

Copy `docs/final-submission.example.json` into the private evidence directory, replace every placeholder, and run:

```bash
python scripts/submission_gate.py evidence/final-submission.json \
  --report evidence/submission-gate-report.json
```

The gate fails unless:

- `repository_commit_sha`, `deployed_build_sha`, current HEAD, repository URL, and license URL identify the same commit;
- runtime IDs differ and the semantic decision cites the stable negative outcome;
- evidence paths remain inside the manifest directory after symlink resolution;
- the ccloud SHA-256 digest and filename match the exact evidence bytes;
- required URLs, UUIDs, retrieval markers, authority markers, screenshots, and testing instructions are complete;
- no credential-like material appears in the public manifest.

## Safety and product-readiness boundaries

- Retrieval influences a recommendation but never authorizes execution.
- Database or Bedrock failure returns a fail-closed `HUMAN_REVIEW` response.
- Required constant-time API-key comparison protects every non-health route.
- TLS defaults to certificate and hostname verification.
- Session, memory type, status, cosine threshold, and a bounded result count constrain recall.
- Deployment errors redact known credentials before printing.
- Generated evidence is untracked until a human deliberately reviews and selects it.
- “Verified outcome” is an upstream operator assertion accepted from a holder of the shared demo key. This application does not independently establish outcome truth, caller identity, or cryptographic provenance; production use needs an authenticated issuer and an auditable verification policy.
- The shared demo key protects the public demo surface but is not tenant identity or session-level authorization.
- `build_sha` binds runtime-reported configuration to a reviewed source commit; it does not attest the deployed ZIP or mutable build inputs.
- The project does not claim that semantic similarity alone proves causality; the stored parent UUID records which memory influenced the decision.
- Review evidence supports a merge decision but never grants merge authority.

## License and reuse disclosure

The public repository is MIT licensed at its root. Liminal Recall was created during the hackathon submission period inside the pre-existing Causal Memory Layer repository for development convenience. The AWS Lambda application, CockroachDB vector schema, Bedrock embedding integration, persistent-memory workflow, ccloud evidence runbook, deployment runner, and demo scenario are new for this submission. The final Devpost entry must identify any reused pre-existing source precisely.

## Current claim boundary

Implementation, protected tests, deployment automation, and proof protocols are checked in. Any live evidence captured from an earlier commit becomes stale after a code change. Before final submission, redeploy the exact final head and recapture:

- live CockroachDB vector-index and query-plan proof;
- redacted ccloud evidence and verified SHA-256 sidecar;
- public AWS Function URL and required private testing credential;
- `/healthz` proof that `build_sha` equals the submitted commit;
- restart-persistence proof with two different runtime IDs and one stable memory UUID;
- sanitized CloudWatch or X-Ray evidence;
- public video under three minutes;
- final screenshots, pinned repository URLs, Devpost URL, and a passing submission-gate report.
