# Devpost submission package

## Project name

Liminal Recall

## Tagline

Persistent, causally linked memory that helps AI agents remember failures and avoid repeating them after restarts.

## Track fit

CockroachDB × AWS Hackathon — Build with Agentic Memory.

## Inspiration

AI agents can call tools and finish workflows, but many lose the reason behind an earlier failure when a process restarts or a new session begins. Ordinary logs preserve events; they do not automatically turn a verified outcome into reusable decision context.

Liminal Recall gives an agent a durable memory loop:

```text
observe -> decide -> record outcome -> restart -> recall -> decide better
```

## What it does

Liminal Recall stores agent observations, decisions, and outcomes in CockroachDB with session boundaries and optional causal parent links. When a later proposed action overlaps with a previously recorded negative outcome, the agent returns `HUMAN_REVIEW` and cites the exact persistent memory records that changed the recommendation.

The system deliberately remains advisory. It records the recommendation but never claims that the external action was executed.

## How we built it

- **CockroachDB Serverless** is the durable memory layer.
- **AWS Lambda** executes the remember, recall, and decision workflow.
- **AWS Lambda Function URL** exposes the public demo API.
- **Python 3.12 and Pydantic** validate the API contract.
- **psycopg 3** connects to CockroachDB using the PostgreSQL wire protocol.
- **AWS SAM** defines the reproducible deployment.
- **GitHub Actions** runs unit tests and Python compilation checks.

The first decision baseline uses normalized tags and token overlap. This is intentionally inspectable and deterministic: judges can see exactly why a memory was selected instead of being asked to trust an opaque similarity score.

## CockroachDB tools used

Final submission fields should name the exact tools demonstrated:

- CockroachDB Serverless cluster as the production persistent memory layer;
- CockroachDB SQL or `ccloud` tooling for schema setup and cluster inspection;
- Managed MCP Server for reviewer-visible inspection, if included in the final live demo.

Do not claim an MCP or CLI integration until the final evidence shows it running.

## AWS services used

- AWS Lambda for agent execution;
- Lambda Function URL for the functional public demo;
- CloudWatch Logs for execution evidence.

Optional hardening before submission: AWS Secrets Manager for `DATABASE_URL`.

## Challenges

The key design challenge was separating memory from execution authority. A remembered failure should influence the next decision, but it should not silently perform or block an external action without review. The API therefore reports `execution.status = NOT_EXECUTED` and stores a decision record with a causal link to the remembered outcome.

## Accomplishments

- durable cross-session agent memory;
- explicit observation, decision, and outcome records;
- causal parent links between outcomes and later decisions;
- reproducible `HUMAN_REVIEW` behavior after a verified-negative memory;
- disposable Lambda compute with durable CockroachDB state;
- open-source tests, schema, deployment template, and evidence protocol.

## What we learned

Agent memory is most useful when it is narrow and inspectable. A small verified-negative memory with a stable ID can be more trustworthy than a large unstructured chat transcript. The system also needs to distinguish “this memory influenced a recommendation” from “this memory authorized an action.”

## What's next

- distributed vector indexing for semantic recall;
- memory supersession and forgetting policies;
- confidence decay for stale observations;
- Bedrock-based explanation generation while preserving deterministic memory citations;
- multi-region failure and recovery evidence;
- authenticated reviewer mode and Secrets Manager integration.

## New-project and reuse disclosure

Liminal Recall is new work created during the hackathon submission period. It is hosted in the Causal Memory Layer repository for development convenience and reuses limited concepts and optional library components from that pre-existing open-source project. The CockroachDB schema, AWS Lambda application, persistent agent-memory workflow, deployment assets, and demo scenario are new for this hackathon. The final submission must link to this directory and identify any reused source file precisely.

## Testing instructions

1. Open the public Lambda Function URL and call `GET /healthz`.
2. Store a negative outcome for session `payments-agent` using `POST /memories`.
3. Call `POST /decisions` with a matching refund retry action.
4. Confirm the result is `HUMAN_REVIEW` and includes the stored outcome ID.
5. Trigger a Lambda cold start or redeploy without clearing CockroachDB.
6. Repeat the decision call and confirm the same persistent memory is cited.
7. Call `GET /memories?session_id=payments-agent` to inspect the outcome and its descendant decision record.

## Demo video script — target 2:35

### 0:00–0:20 — problem

“Agents restart, retry, and move across processes. When they forget a previous failure, they repeat it. Liminal Recall turns verified outcomes into durable decision memory.”

### 0:20–0:40 — architecture

Show the architecture diagram: public request to AWS Lambda, decision engine, CockroachDB memory records, and causal links.

### 0:40–1:05 — clean decision

Call `/decisions` for a read-only report in a fresh session. Show `ALLOW_WITH_MONITORING`, no cited negative memories, and `NOT_EXECUTED`.

### 1:05–1:30 — store failure memory

Store the double-refund negative outcome. Show the returned stable UUID and the record in CockroachDB.

### 1:30–1:55 — agent learns

Call `/decisions` for “Retry the customer refund payment.” Show `HUMAN_REVIEW`, the exact earlier memory ID, and the newly persisted decision record with its parent link.

### 1:55–2:15 — persistence proof

Show a fresh Lambda execution environment or redeploy. Repeat the call and show that CockroachDB returns the prior memory after the compute process changed.

### 2:15–2:35 — close

“CockroachDB gives the agent durable memory; AWS runs disposable agent compute; causal IDs make every changed decision reviewable.”

## Final fields still required

- public repository URL pinned to the final commit;
- public AWS demo URL;
- public YouTube or Vimeo video under three minutes;
- screenshots of the decision flow and CockroachDB records;
- exact CockroachDB tooling used;
- exact AWS services used;
- live-test instructions valid through the judging period.
