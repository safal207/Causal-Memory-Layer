# Judging scorecard and evidence map

This file turns each judging criterion into a concrete claim, artifact, and pass condition. A claim is not ready until its evidence is attached to one exact final commit and matching live deployment.

## Stage one: eligibility — pass/fail

| Requirement | Implementation | Required evidence before submission |
|---|---|---|
| Agentic application | `remember -> recall -> decide -> persist decision` | Public video and API responses |
| CockroachDB persistent memory | `agent_memories` is the only durable memory source | Same memory UUID recalled after a new Lambda runtime |
| CockroachDB tool 1 | Distributed Vector Indexing with cosine search | `SHOW INDEX`, `EXPLAIN`, and response `retrieval.tool=distributed_vector_index` |
| CockroachDB tool 2 | `ccloud` CLI used by the evidence agent | Redacted live JSON plus a verified digest-and-filename sidecar |
| AWS service | Lambda executes the API and Bedrock generates embeddings | Function URL, exact `build_sha`, CloudWatch/X-Ray evidence, and IAM policy |
| Public open-source repository | This directory plus repository license | Repository and license URLs pinned to the deployed SHA |
| Functional demo | Public health endpoint plus authenticated application routes | Private key and instructions valid through September 15, 2026 |
| Video under three minutes | Script targets 2:35 | Public YouTube or Vimeo URL |

## Stage two: five equally weighted criteria

### 1. Agentic Memory Design

**Claim:** Memory changes a later decision rather than merely decorating a prompt.

Evidence:

- observations, decisions, and outcomes are distinct records;
- a later decision cites exact memory UUIDs;
- the stored decision has a causal parent link to the influencing outcome;
- memory survives replacement of disposable Lambda compute;
- semantic recall is constrained by session, kind, status, and cosine threshold;
- the live proof uses different wording and non-overlapping tags.

Target proof: a verified duplicate-refund outcome causes “Send the customer reimbursement again” to return `HUMAN_REVIEW` after the Lambda runtime ID changes.

### 2. Technical Implementation

**Claim:** Both required CockroachDB tools and AWS services are integrated safely and observably.

Evidence:

- Bedrock Titan Text Embeddings V2 produces normalized 256-dimensional vectors;
- the template, embedder, and CockroachDB schema share the same fixed dimension;
- CockroachDB stores vectors beside transactional memory records;
- a prefix-aware distributed vector index accelerates filtered cosine search;
- CockroachDB connections default to `sslmode=verify-full`;
- ccloud emits structured evidence that is redacted and checksum-bound;
- focused tests cover dimensions, retrieval mode, TLS, authentication, causal linkage, SHA binding, and evidence integrity;
- protected repository CI runs against the exact PR head.

Target proof: `EXPLAIN` shows a vector-search plan and the live API reports `retrieval.mode=cockroachdb_vector_cosine`.

### 3. Real-World Impact

**Claim:** The project prevents agents from repeating costly operational failures in refunds, payouts, deployments, and incident remediation.

Evidence:

- the demo uses a duplicate-refund incident caused by a non-idempotent retry;
- the system recalls the failure when later wording and tags differ;
- the recommendation is reviewable and does not silently execute an action;
- the same contract can support healthcare, security, fintech, and infrastructure workflows.

Target proof: the video shows the exact earlier outcome responsible for the safer recommendation.

### 4. Product Readiness

**Claim:** The demo has explicit authority, security, resilience, source-binding, artifact-identity non-claim, and observability boundaries.

Evidence:

- failures return `HUMAN_REVIEW` rather than a permissive decision;
- every decision reports `execution.status=NOT_EXECUTED`;
- required constant-time `x-demo-key` authentication protects every non-health route and fails closed when configuration is absent;
- verified TLS protects database credentials and memory content;
- X-Ray and CloudWatch provide execution evidence;
- secrets are excluded from committed evidence;
- evidence paths cannot escape the manifest directory;
- checksum bytes and filename are verified;
- `runtime_instance_id` proves process replacement;
- `build_sha` shows that both runtime responses report the reviewed source SHA configured at deployment; it is not an artifact-byte attestation.

Target proof: unauthorized requests fail, the deployed SHA matches the submitted commit, a forced new runtime receives the old memory, and no credential appears in evidence.

### 5. Creativity and Originality

**Claim:** Liminal Recall treats memory as a causal, auditable safety primitive rather than chat history or generic RAG.

Evidence:

- verified outcomes are first-class memory records;
- recalled memories have stable IDs and causal descendants;
- semantic relevance and execution authority remain separate;
- recommendations can be reproduced and reviewed after restarts;
- the evidence package is itself causally bound to the code that produced it.

Target proof: the demo contrasts ordinary logs with a durable outcome that directly changes a later decision and remains attributable to one exact build.

## Honest readiness scale

- **98% submission readiness:** every automated check is green; live CockroachDB, ccloud, Bedrock, Lambda, exact-SHA proof, restart proof, screenshots, final URLs, and video are attached.
- **Not a 98% win guarantee:** ranking depends on competing entries and judges. The controllable goal is to remove almost every avoidable eligibility, reliability, trust, and presentation failure.
