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

Liminal Recall stores observations, decisions, and verified outcomes in CockroachDB. Amazon Bedrock Titan Text Embeddings V2 converts memories and proposed actions into normalized 256-dimensional vectors. CockroachDB Distributed Vector Indexing retrieves semantically related negative outcomes within the same agent session, even when the later wording and tags differ.

When a relevant failure is recalled, the agent:

- returns `HUMAN_REVIEW`;
- cites the exact persistent memory UUIDs that changed the recommendation;
- stores the new decision with a causal parent link to the most influential outcome;
- reports `execution.status = NOT_EXECUTED` and never pretends the external action occurred.

Every response also includes a `runtime_instance_id`. The public `/healthz` response additionally exposes `build_sha`. During the demo, Lambda compute is replaced, the runtime ID changes, the configured reviewed source SHA remains identical, and the earlier CockroachDB memory UUID remains available. This separates process-replacement evidence, durable-memory evidence, and the runtime-reported source binding. The SHA is not an artifact-byte or dependency attestation.

## How we built it

### CockroachDB

- **CockroachDB Cloud** is the only durable memory layer.
- Transactional records store content, tags, status, confidence, timestamps, and causal parent UUIDs.
- **Distributed Vector Indexing** performs cosine similarity search over 256-dimensional Bedrock embeddings.
- Prefix filters constrain vector search to the exact `session_id`, `kind = outcome`, and `status = negative` partition.
- Connections default to `sslmode=verify-full` with the packaged CockroachDB root certificate when the URL does not specify an explicit policy.
- **ccloud CLI** is used by a checked-in evidence agent. It executes structured commands for identity, organization settings, and cluster state, redacts sensitive values, and creates a SHA-256 integrity sidecar.

### AWS

- **AWS Lambda** runs the `remember / recall / decide / persist` workflow.
- **Amazon Bedrock Titan Text Embeddings V2** creates normalized embeddings.
- **Lambda Function URL** exposes the functional demo and public health proof.
- **CloudWatch and X-Ray** provide execution and trace evidence.
- AWS SAM defines reproducible deployment, least-purpose Bedrock permission, a required demo key, fixed vector dimensions, and the exact reviewed `BuildSha`.

### Engineering and safety

- Python 3.12, Pydantic, psycopg 3, and boto3;
- fail-closed behavior: database or embedding failure returns `HUMAN_REVIEW`;
- required constant-time `x-demo-key` authentication for every non-health route;
- Lambda rejects memory and decision access when the runtime key is missing;
- verified CockroachDB TLS defaults;
- stable memory UUIDs and explicit causal links for reviewability;
- clean-worktree deployment and exact Git-SHA binding through `/healthz`;
- different-wording semantic proof with non-overlapping tags;
- generated cloud evidence is ignored by Git until a human reviews and deliberately selects it;
- a fail-closed submission gate rejects placeholders, escaped evidence paths, stale SHAs, invalid URLs, identical runtime IDs, malformed or mismatched checksums, and credential-like values;
- focused tests plus protected repository CI for changed decisions, vector retrieval, Bedrock request shape, transport security, evidence integrity, and authority separation.

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

The deployment evidence agent runs current `ccloud auth whoami`, `ccloud settings`, and `ccloud cluster info` commands with structured-output compatibility handling. It redacts credentials before writing the evidence manifest and records a checksum. The final gate strictly recomputes the digest and requires the sidecar filename to match the evidence file.

Final submission language must only say these tools were used after the live vector plan and ccloud evidence are recaptured from the exact submitted deployment.

## AWS services used

- AWS Lambda — agent execution;
- Amazon Bedrock — Titan Text Embeddings V2 inference;
- Lambda Function URL — functional demo and build-identity endpoint;
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

The product value is not merely “remember more.” It is “remember the operator-attested failure that should change this decision, explain exactly which memory mattered, bind the runtime report to reviewed source, and remain safe when infrastructure restarts.” The demo operator supplies the negative-outcome classification; the service does not independently verify its truth or provenance.

## Challenges

### Separating relevance from authority

A semantically similar failure should influence a recommendation, but similarity alone should never authorize or execute an action. Liminal Recall therefore remains advisory and stores the causal relationship for human review.

### Proving semantic recall honestly

Using identical text for the stored outcome and later request produces a trivial zero-distance result. The final proof stores a duplicate-refund failure, then asks to “Send the customer reimbursement again” with independent tags. The original outcome UUID must still be cited.

### Proving persistence and code identity honestly

A repeated request in the same warm Lambda process does not prove durable memory, and a local Git SHA does not prove which code is deployed. The demo embeds the exact clean-worktree SHA in Lambda configuration, verifies it through `/healthz`, forces process replacement, and then shows a changed runtime UUID with the same build SHA and CockroachDB outcome UUID.

### Making platform-tool use reviewable

The project does not merely initialize CockroachDB tools. Runtime responses identify vector retrieval, SQL evidence shows the vector-search plan, and the ccloud evidence agent produces structured, redacted control-plane evidence whose bytes and filename are checksum-bound.

## Accomplishments

- durable cross-session and cross-process agent memory;
- semantic recall through CockroachDB Distributed Vector Indexing;
- Bedrock-generated normalized embeddings fixed to the database schema;
- explicit observation, decision, and outcome records;
- causal parent links between failures and later decisions;
- reproducible `HUMAN_REVIEW` from genuinely different semantic input;
- advisory-only execution boundary and fail-closed behavior;
- required authenticated write and decision routes;
- verified TLS defaults for CockroachDB;
- exact reviewed-SHA binding across Git, SAM, Lambda health, runtime proof, manifest, and pinned repository URLs;
- machine-readable ccloud deployment evidence with verified checksum;
- evidence-directory containment including symlink resolution;
- protected CI coverage for semantic recall, causal linkage, Titan embedding, redaction, transport, deployment identity, and submission contracts;
- one-command AWS/CockroachDB deployment and restart-proof runner;
- AWS SAM deployment, architecture, scorecard, causal commit graph, and video protocol.

## What we learned

Agent memory is most trustworthy when it is narrow, durable, and inspectable. A stable operator-attested outcome UUID can be more useful than a large unstructured transcript. Vector search improves recall, but the system still needs explicit boundaries between “this memory is relevant,” “this memory influenced the recommendation,” “this action was authorized,” and “this runtime reported the reviewed source SHA.”

We also learned that process restarts, data durability, semantic relevance, execution safety, source-configuration binding, artifact identity, and submission evidence are separate claims and require separate proofs. This demo does not provide artifact-byte attestation.

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

1. Open `GET /healthz` and record `build_sha` plus `runtime_instance_id`.
2. Confirm `build_sha` equals the exact submitted repository commit.
3. Use the private `x-demo-key` credential for every remaining request.
4. Store a verified-negative duplicate-refund outcome using `POST /memories`.
5. Save the returned outcome UUID.
6. Call `POST /decisions` with different wording: “Send the customer reimbursement again,” using tags `customer` and `payout`.
7. Confirm `HUMAN_REVIEW`, `cockroachdb_vector_cosine`, `distributed_vector_index`, and the exact outcome UUID.
8. Confirm the stored decision has `parent_memory_id` equal to the outcome UUID.
9. Force a fresh Lambda execution environment without clearing CockroachDB.
10. Confirm `runtime_instance_id` changes while `build_sha` stays identical.
11. Repeat the decision and confirm the original outcome UUID is still cited.
12. Review sanitized `SHOW INDEX`, vector `EXPLAIN`, ccloud JSON, checksum, and CloudWatch/X-Ray evidence.

The checked-in `scripts/live_deploy.py all` command automates this sequence and fails if the repository is dirty, the key is absent, the runtime reports a different build SHA, the semantic decision misses the outcome, or the runtime ID does not change. The temporary `x-demo-key` credential must be shared privately through Devpost and remain valid through judging.

## Demo video script — target 2:35

### 0:00–0:18 — costly failure

“An agent retries a refund, forgets the earlier outcome after a restart, and pays twice. Logs preserve events; durable decision memory prevents repetition.”

### 0:18–0:35 — architecture and trust boundaries

Show Lambda, Bedrock embeddings, CockroachDB vector memory, causal links, required demo-key authentication, and the build-SHA evidence path.

### 0:35–1:00 — store verified outcome

Store the duplicate-refund outcome. Show its stable UUID and CockroachDB record with a 256-dimensional embedding.

### 1:00–1:28 — semantic recall changes the decision

Ask, “Send the customer reimbursement again,” with independent tags. Show `HUMAN_REVIEW`, vector retrieval, the exact earlier UUID, `NOT_EXECUTED`, and the causal decision link.

### 1:28–1:50 — prove platform and evidence integrity

Show the CockroachDB vector index/query plan, redacted ccloud JSON, and matching SHA-256 sidecar.

### 1:50–2:15 — show source binding and persistence

Show `/healthz` with the submitted `build_sha`, replace the Lambda runtime, then show a different `runtime_instance_id`, the same build SHA, and the same CockroachDB memory UUID.

### 2:15–2:35 — close

“CockroachDB gives agents durable, searchable memory. AWS runs disposable compute. Causal IDs and build identity make every safer decision reviewable without giving memory permission to act.”

## Submission readiness gate

Copy `docs/final-submission.example.json` into the private evidence directory, replace every placeholder, and run:

```bash
python scripts/submission_gate.py evidence/final-submission.json \
  --report evidence/submission-gate-report.json
```

The gate must return `PASS` before submission. It binds the manifest to the current reviewed head, the deployed build SHA, pinned repository and license URLs, contained evidence paths, and the exact ccloud evidence digest and filename.

## Final fields still required from the exact final deployment

- final public repository commit URL pinned to the submitted code;
- matching `repository_commit_sha` and `deployed_build_sha`;
- public AWS demo URL;
- valid private `x-demo-key` credential;
- public YouTube or Vimeo video under three minutes;
- screenshots of the vector plan, decision flow, causal record, build SHA, and changed runtime ID;
- redacted ccloud evidence generated from the live cluster plus verified sidecar;
- final AWS and CockroachDB tool disclosures;
- testing availability through the end of judging;
- final Devpost submission URL;
- a passing final-submission gate report.
