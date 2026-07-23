# Judging scorecard and evidence map

This file turns each judging criterion into a concrete claim, artifact, and pass condition. A claim is not considered ready until its evidence is attached to the final commit and live deployment.

## Stage one: eligibility — pass/fail

| Requirement | Implementation | Required evidence before submission |
|---|---|---|
| Agentic application | `remember -> recall -> decide -> persist decision` | Public video and API responses |
| CockroachDB persistent memory | `agent_memories` is the only durable memory source | Same memory UUID recalled after a new Lambda runtime |
| CockroachDB tool 1 | Distributed Vector Indexing with cosine search | `SHOW INDEX`, `EXPLAIN`, and response `retrieval.tool=distributed_vector_index` |
| CockroachDB tool 2 | `ccloud` CLI used by the evidence agent runbook | Redacted `evidence/ccloud-evidence.json` generated from live commands |
| AWS service | Lambda executes the API and Bedrock generates embeddings | Function URL, CloudWatch/X-Ray evidence, and IAM policy |
| Public open-source repository | This directory plus repository license | Final commit URL and visible open-source license |
| Functional demo | Public Lambda Function URL | Test instructions valid through September 15, 2026 |
| Video under three minutes | Script targets 2:35 | Public YouTube or Vimeo URL |

## Stage two: five equally weighted criteria

### 1. Agentic Memory Design

**Claim:** Memory changes a later decision rather than merely decorating a prompt.

Evidence:

- observations, decisions, and outcomes are stored as distinct records;
- a later decision cites exact memory UUIDs;
- the stored decision has a causal parent link to the outcome that influenced it;
- memory survives replacement of disposable Lambda compute;
- semantic recall is constrained by session, kind, status, and a cosine threshold.

Target proof: a verified double-refund outcome causes a semantically related retry action to return `HUMAN_REVIEW` after the Lambda runtime ID changes.

### 2. Technical Implementation

**Claim:** Both required CockroachDB tools and AWS services are integrated safely and observably.

Evidence:

- Bedrock Titan Text Embeddings V2 produces normalized 256-dimensional vectors;
- CockroachDB stores vectors beside transactional memory records;
- a prefix-aware distributed vector index accelerates filtered cosine search;
- `ccloud` emits structured JSON that the evidence script redacts and preserves;
- tests cover embedding request shape, retrieval mode, authentication, causal linkage, and fail-closed behavior;
- root protected CI includes the semantic retrieval and Titan embedding contract, preventing the hackathon implementation from drifting behind a green parent-repository check.

Target proof: `EXPLAIN` shows a vector-search plan and the live API reports `retrieval.mode=cockroachdb_vector_cosine`.

### 3. Real-World Impact

**Claim:** The project prevents agents from repeating costly operational failures in workflows such as refunds, payouts, deployments, and incident remediation.

Evidence:

- the demo uses a duplicate-refund incident caused by a non-idempotent retry;
- the system recalls the failure even when later wording differs;
- the recommendation is reviewable and does not silently execute an action;
- the same contract can support healthcare, security, fintech, and infrastructure workflows.

Target proof: the video quantifies the failure mode and shows the exact earlier outcome responsible for the safer recommendation.

### 4. Product Readiness

**Claim:** The demo has explicit authority, security, resilience, and observability boundaries.

Evidence:

- failures return `HUMAN_REVIEW` rather than a permissive decision;
- every decision reports `execution.status=NOT_EXECUTED`;
- optional constant-time `x-demo-key` authentication protects non-health routes;
- Lambda reserved concurrency limits public-demo blast radius;
- X-Ray and CloudWatch provide execution evidence;
- secrets are excluded from committed evidence;
- `runtime_instance_id` proves process replacement without confusing it with database durability.

Target proof: unauthorized requests fail, a forced new runtime receives the old memory, and no credential appears in screenshots or repository files.

### 5. Creativity and Originality

**Claim:** Liminal Recall treats memory as a causal, auditable safety primitive rather than chat history or generic RAG.

Evidence:

- verified outcomes are first-class memory records;
- recalled memories have stable IDs and causal descendants;
- semantic relevance and execution authority remain separate;
- recommendations can be reproduced and reviewed after restarts.

Target proof: the demo contrasts ordinary logs with a memory record that directly changes a later decision.

## Honest readiness scale

- **98% submission readiness:** every automated check is green; live CockroachDB, `ccloud`, Bedrock, Lambda, restart proof, screenshots, final URLs, and video are attached.
- **Not a 98% win guarantee:** ranking depends on competing entries and judges. The controllable goal is to remove almost every avoidable eligibility, reliability, and presentation failure.
