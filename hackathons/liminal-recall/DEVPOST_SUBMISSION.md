# Devpost submission package

## Project name

Liminal Recall

## Tagline

Causally auditable memory that helps AI agents remember verified failures and avoid repeating them after restarts.

## Track fit

CockroachDB × AWS Hackathon — Build with Agentic Memory.

## Inspiration

Agents are increasingly trusted with refunds, deployments, incident response, and other workflows where a repeated mistake can cost money or harm users. Yet a restarted process often remembers only logs or chat history, not the exact verified outcome that should change the next decision.

A payment agent that forgets a non-idempotent retry can send the same refund twice. Liminal Recall turns that outcome into durable, searchable, causally linked decision memory.

```text
observe -> decide -> record outcome -> restart -> semantic recall -> decide safer
```

## What it does

Liminal Recall stores observations, decisions, and verified outcomes in CockroachDB. Amazon Bedrock Titan Text Embeddings V2 converts memories and proposed actions into normalized vectors. CockroachDB Distributed Vector Indexing retrieves semantically related negative outcomes within the same agent session, even when the later wording differs.

When a relevant failure is recalled, the agent:

- returns `HUMAN_REVIEW`;
- cites the exact persistent memory UUIDs that changed the recommendation;
- stores the new decision with a causal parent link to the most influential outcome;
- reports `execution.status = NOT_EXECUTED` and never pretends the external action occurred.

Every response also includes a `runtime_instance_id`. During the demo, Lambda compute is replaced, the runtime ID changes, and the earlier CockroachDB memory UUID remains available. This distinguishes process replacement from durable memory.

## How we built it

### CockroachDB

- **CockroachDB Cloud** is the only durable memory layer.
- Transactional records store content, tags, status, confidence, timestamps, and causal parent UUIDs.
- **Distributed Vector Indexing** performs cosine similarity search over 256-dimensional Bedrock embeddings.
- Prefix filters constrain the vector search to the exact `session_id`, `kind = outcome`, and `status = negative` partition.
- **ccloud CLI** is used by a checked-in evidence agent. It executes structured JSON commands for identity, organization, and cluster state, redacts sensitive keys and credential-like strings, and creates a SHA-256 integrity sidecar.

### AWS

- **AWS Lambda** runs the `remember / recall / decide / persist` workflow.
- **Amazon Bedrock Titan Text Embeddings V2** creates normalized embeddings for memories and proposed actions.
- **Lambda Function URL** exposes the public functional demo.
- **CloudWatch and X-Ray** provide execution and trace evidence.
- AWS SAM defines the reproducible deployment and least-purpose Bedrock permission.

### Engineering and safety

- Python 3.12, Pydantic, psycopg 3, and boto3;
- fail-closed behavior: database or embedding failure returns `HUMAN_REVIEW`;
- optional constant-time `x-demo-key` authentication for non-health routes;
- reserved Lambda concurrency to bound public-demo blast radius;
- deterministic memory UUIDs and explicit causal links for reviewability;
- one-command live deployment and process-replacement evidence runner;
- generated cloud evidence is ignored by Git until a human reviews and deliberately selects it;
- a fail-closed submission gate rejects placeholders, missing evidence, invalid URLs, identical runtime IDs, and credential-like values;
- focused tests plus protected repository CI for changed decisions, vector retrieval, Bedrock request shape, evidence redaction, and authority separation.

## CockroachDB tools used

### 1. Distributed Vector Indexing

The live application stores Bedrock embeddings in `VECTOR(256)` and queries them with cosine distance. The index uses exact prefix columns for session, memory kind, and status. The final evidence includes `SHOW INDEX`, a live `EXPLAIN` plan showing vector search, and an API response with:

```json
{
  "retrieval": {
    "mode": "cockroachdb_vector_cosine",
    "memory_layer": "cockroachdb",
    "tool": "distributed_vector_index"
  }
}
```

### 2. ccloud CLI

The deployment evidence agent runs current `ccloud auth whoami`, `ccloud organization get`, and `ccloud cluster info` commands using structured JSON output. It redacts credentials before writing the evidence manifest and records a checksum. This makes infrastructure proof repeatable and machine-readable instead of relying only on manually curated screenshots.

Final submission language must only say these tools were used after the live vector plan and ccloud evidence are captured from the deployed cluster.

## AWS services used

- AWS Lambda — agent execution;
- Amazon Bedrock — Titan Text Embeddings V2 inference;
- Lambda Function URL — functional public demo;
- CloudWatch Logs and AWS X-Ray — observability evidence.

## Why this is agentic memory rather than ordinary logging or generic RAG

Logs preserve events but do not necessarily change a later decision. Generic RAG often retrieves text without a stable authority or causal contract.

Liminal Recall makes a verified outcome a first-class memory object. A later recommendation cites exact memory IDs, and the stored decision points back to the outcome that influenced it. Semantic relevance affects advice, but it never grants execution authority.

## Real-world impact

The first demo prevents a duplicate refund after a non-idempotent retry, but the same pattern applies to:

- payout and settlement agents;
- deployment and rollback agents;
- security incident remediation;
- healthcare workflow assistants;
- customer-support agents handling irreversible actions.

The product value is not merely “remember more.” It is “remember the verified failure that should change this decision, explain exactly which memory mattered, and remain safe when infrastructure restarts.”

## Challenges

### Separating relevance from authority

A semantically similar failure should influence a recommendation, but similarity alone should never authorize or execute an action. Liminal Recall therefore remains advisory and stores the causal relationship for human review.

### Proving persistence honestly

A repeated request in the same warm Lambda process does not prove durable memory. The demo exposes a runtime UUID, forces process replacement, and then shows a changed runtime UUID with the same CockroachDB outcome UUID.

### Making platform-tool use reviewable

The project does not merely initialize CockroachDB tools. Runtime responses identify vector retrieval, SQL evidence shows the vector-search plan, and the ccloud evidence agent produces structured, redacted control-plane evidence.

## Accomplishments

- durable cross-session and cross-process agent memory;
- semantic recall through CockroachDB Distributed Vector Indexing;
- Bedrock-generated normalized embeddings;
- explicit observation, decision, and outcome records;
- causal parent links between failures and later decisions;
- reproducible `HUMAN_REVIEW` after a semantically related negative outcome;
- advisory-only execution boundary and fail-closed behavior;
- machine-readable ccloud deployment evidence with checksum;
- protected CI coverage for semantic recall, causal linkage, Titan embedding, redaction, and submission contracts;
- one-command AWS/CockroachDB deployment and restart-proof runner;
- fail-closed final-submission manifest validator;
- AWS SAM deployment, architecture, scorecard, and video protocol.

## What we learned

Agent memory is most trustworthy when it is narrow, durable, and inspectable. A stable verified-outcome UUID can be more useful than a large unstructured transcript. Vector search improves recall, but the system still needs explicit boundaries between “this memory is relevant,” “this memory influenced the recommendation,” and “this action was authorized.”

We also learned that process restarts, data durability, semantic relevance, execution safety, and submission evidence are separate claims and should have separate proofs.

## What's next

- memory supersession, correction, and forgetting policies;
- confidence decay for stale observations;
- regional failure and recovery tests;
- calibrated similarity thresholds by workflow risk;
- authenticated reviewer dashboards;
- AWS Secrets Manager for long-lived deployments;
- multi-parent causal graphs for decisions influenced by several outcomes;
- controlled execution adapters requiring explicit human authorization.

## New-project, license, and reuse disclosure

Liminal Recall is new work created during the hackathon submission period. It is hosted in the pre-existing Causal Memory Layer repository for development convenience. The repository has an MIT license at its root. The Lambda application, CockroachDB vector schema, Bedrock integration, ccloud evidence agent, live deployment runner, submission gate, persistent-memory workflow, deployment assets, and demo scenario are new for this submission.

The final entry must identify any reused pre-existing source file precisely and must not imply that the entire surrounding repository was created during the hackathon.

## Testing instructions

1. Open `GET /healthz` and record `runtime_instance_id`.
2. Store a verified-negative duplicate-refund outcome using `POST /memories`.
3. Save the returned outcome UUID.
4. Call `POST /decisions` with different wording: “Send the customer reimbursement again.”
5. Confirm `HUMAN_REVIEW`, `cockroachdb_vector_cosine`, `distributed_vector_index`, and the exact outcome UUID.
6. Confirm the stored decision has `parent_memory_id` equal to the outcome UUID.
7. Force a fresh Lambda execution environment without clearing CockroachDB.
8. Confirm `runtime_instance_id` changes.
9. Repeat the decision and confirm the original outcome UUID is still cited.
10. Review sanitized `SHOW INDEX`, vector `EXPLAIN`, ccloud JSON, and CloudWatch/X-Ray evidence.

The checked-in `scripts/live_deploy.py all` command automates this sequence and fails if any required marker is missing. When a demo key is enabled, Devpost testing instructions must include the temporary `x-demo-key` credential privately and keep it valid through the judging period.

## Demo video script — target 2:35

### 0:00–0:18 — costly failure

“An agent retries a refund, forgets the earlier outcome after a restart, and pays twice. Logs preserve events; durable decision memory prevents repetition.”

### 0:18–0:35 — architecture

Show Lambda, Bedrock embeddings, CockroachDB vector memory, causal links, and the ccloud evidence agent.

### 0:35–1:00 — store verified outcome

Store the duplicate-refund outcome. Show its stable UUID and CockroachDB record with an embedding.

### 1:00–1:28 — semantic recall changes the decision

Ask, “Send the customer reimbursement again,” using different wording. Show `HUMAN_REVIEW`, vector retrieval, the exact earlier UUID, `NOT_EXECUTED`, and the causal decision link.

### 1:28–1:50 — prove the platform tools

Show the CockroachDB vector index/query plan and the redacted ccloud JSON evidence.

### 1:50–2:15 — prove persistence

Replace the Lambda runtime. Show a different `runtime_instance_id`, repeat the request, and show the same CockroachDB memory UUID.

### 2:15–2:35 — close

“CockroachDB gives agents durable, searchable memory. AWS runs disposable compute. Causal IDs make every safer decision reviewable without giving memory permission to act.”

## Submission readiness gate

Copy `docs/final-submission.example.json` into the private evidence directory, replace every placeholder, and run:

```bash
python scripts/submission_gate.py evidence/final-submission.json \
  --report evidence/submission-gate-report.json
```

The gate must return `PASS` before submission. Generated evidence remains ignored by Git until each selected artifact is reviewed and deliberately added.

## Final fields still required from the live deployment

- final public repository commit URL pinned to the submitted code;
- public AWS demo URL;
- valid private testing credential if demo-key protection is enabled;
- public YouTube or Vimeo video under three minutes;
- screenshots of the vector plan, decision flow, causal record, and changed runtime ID;
- redacted ccloud evidence generated from the live cluster;
- final AWS and CockroachDB tool disclosures;
- testing availability through the end of judging;
- final Devpost submission URL;
- a passing final-submission gate report.
