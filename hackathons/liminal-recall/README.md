# Liminal Recall

**CockroachDB × AWS Hackathon — Build with Agentic Memory**

Liminal Recall is a causally auditable memory service for AI agents. It stores observations, decisions, and outcomes in CockroachDB, then uses those memories to make later actions safer and more consistent after restarts, retries, and regional failures.

## What the demo proves

1. An agent stores a verified negative outcome.
2. The process can restart without losing that memory.
3. A later, similar action retrieves the earlier outcome.
4. The agent returns `HUMAN_REVIEW` and cites the exact memory IDs that changed its decision.
5. AWS Lambda executes the agent workflow; CockroachDB is the persistent memory layer.

## Architecture

```text
Client / demo UI
      |
      v
AWS Lambda Function URL
      |
      +--> Liminal Recall decision engine
      |       |
      |       +--> remember / recall / decide
      |
      +--> CockroachDB Serverless
              |
              +--> observations
              +--> decisions
              +--> outcomes
              +--> causal parent links
```

See [`docs/architecture.md`](docs/architecture.md).

## Endpoints

- `GET /healthz`
- `POST /memories`
- `GET /memories?session_id=<id>&limit=20`
- `POST /decisions`

### Store a memory

```bash
curl -X POST "$BASE_URL/memories" \
  -H 'content-type: application/json' \
  -d '{
    "session_id": "checkout-agent",
    "kind": "outcome",
    "content": "Refund was sent twice after retry without idempotency key",
    "tags": ["refund", "payment", "retry"],
    "status": "negative",
    "confidence": 0.98
  }'
```

### Ask for a decision

```bash
curl -X POST "$BASE_URL/decisions" \
  -H 'content-type: application/json' \
  -d '{
    "session_id": "checkout-agent",
    "proposed_action": "Retry the customer refund payment",
    "tags": ["refund", "payment", "retry"]
  }'
```

Expected result after the negative memory exists:

```json
{
  "decision": "HUMAN_REVIEW",
  "reason": "A prior negative outcome overlaps with this action.",
  "memory_ids": ["..."]
}
```

## Local validation

```bash
cd hackathons/liminal-recall
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
python -m py_compile app/*.py
```

## AWS deployment

The included `template.yaml` deploys an AWS Lambda Function URL. Package with AWS SAM:

```bash
sam build
sam deploy --guided \
  --parameter-overrides DatabaseUrl="$DATABASE_URL"
```

`DATABASE_URL` must be the CockroachDB connection string. Store it as an encrypted Lambda environment value or migrate it to AWS Secrets Manager before a public production deployment.

## CockroachDB setup

Run [`schema.sql`](schema.sql) against a CockroachDB Serverless cluster:

```bash
cockroach sql --url "$DATABASE_URL" --file schema.sql
```

The final hackathon build will also document use of CockroachDB Cloud tooling and the Managed MCP Server for reviewer-visible database inspection.

## New-project and reuse disclosure

This hackathon application is newly created during the submission period. It reuses only narrow ideas and optional library code from the pre-existing open-source Causal Memory Layer project. The AWS Lambda application, CockroachDB persistence model, agent-memory workflow, deployment assets, and submission demo are new work for this hackathon. Any reused code will be identified precisely in the final submission.

## Current boundary

This first scaffold does not claim a live CockroachDB or AWS deployment yet. A valid submission still requires:

- a live CockroachDB cluster;
- a public AWS-hosted demo;
- evidence that memory survives process restart;
- a public video under three minutes;
- final Devpost text and testing instructions.
