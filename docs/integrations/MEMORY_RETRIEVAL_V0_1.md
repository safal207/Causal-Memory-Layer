# CML Memory Retrieval v0.1

CML Memory Retrieval surfaces relevant **accepted** engineering memory while a pull request is still under review.

It completes the first closed learning cycle:

```text
merged pull request
        ↓
reviewed Memory Pack proposal
        ↓
accepted memory on main
        ↓
new pull request
        ↓
relevant accepted memory comment
```

The retrieval comment is advisory. It cannot approve, execute, modify, or merge code.

## GitHub lifecycle

The protected workflow runs when an open pull request is:

- opened;
- reopened;
- synchronized with a new head commit;
- edited;
- moved from draft to ready for review.

A manual `workflow_dispatch` mode accepts an open pull-request number for backfill and live validation.

For each eligible event, the workflow:

1. checks out the exact trusted base SHA;
2. never checks out or executes the source branch;
3. reads the pull-request title, body, head/base SHAs, and changed filenames through the GitHub API;
4. loads accepted Memory Packs only from `.cml/memory/cycles/*.json` at the exact base SHA;
5. validates schema, identity, graph connectivity, evidence references, privacy, and authority boundaries;
6. ranks publishable memories deterministically;
7. creates or updates one managed `Relevant CML Memory` comment;
8. uploads an exact-run/exact-attempt evidence artifact.

Generated memory pull requests and memory-only changes are skipped to prevent recursion and noise.

## Retrieval algorithm

Version 0.1 deliberately uses no embedding API and no language model.

The query contains weighted tokens from:

| Pull-request field | Weight |
|---|---:|
| title | 4 |
| changed filenames | 3 |
| body | 1 |

Accepted memory contains weighted tokens from graph nodes:

| Memory node | Weight |
|---|---:|
| lesson | 6 |
| situation | 5 |
| action | 5 |
| cause | 4 |
| constraint | 4 |
| option | 3 |
| outcome | 3 |
| check | 2 |
| evidence | 1 |

Nodes on the selected best-known path receive an additional weight. Manifest and evidence descriptions contribute bounded supporting tokens.

Ranking uses corpus-level inverse document frequency and cosine similarity. A result must share at least two meaningful tokens and exceed the minimum score. Ties are resolved by exact `pack_id` and path, making output independent of API ordering or Python hash seed.

At most three memories are shown.

## Comment format

Each result contains:

- the prior situation;
- the accepted selected path;
- up to three constraints;
- matched terms explaining the ranking;
- deterministic relevance score;
- exact Memory Pack path;
- exact source commit;
- full pack ID;
- evidence-record count.

Accepted-memory text is flattened, bounded, HTML-escaped, stripped of the managed-comment marker, and prevented from creating Markdown code spans.

The managed marker is:

```html
<!-- cml-retrieval-v0.1 -->
```

Only a comment authored by `github-actions[bot]` with that marker may be updated. A human comment containing the marker is never overwritten.

## Privacy policy

The workflow applies privacy **before ranking**.

### Public repository

Only packs satisfying both conditions are publishable:

```text
visibility = public
contains_private_data = false
```

Team, partner, private, or private-data packs are counted as withheld but their situation, path, constraints, and evidence are not rendered.

### Internal repository

`team`, `partner`, and `public` packs without private data may be rendered.

### Private repository

Repository-local accepted packs may be rendered because the pull-request conversation has the repository's access boundary.

Unknown repository visibility uses the public-repository rule.

## Accepted-memory validation

Every candidate must:

- use `cml-memory-pack-v1`;
- have exact known fields at every schema level;
- have a canonical SHA-256 `pack_id`;
- bind to the current repository;
- bind to a full source commit SHA;
- grant neither merge nor execution authority;
- contain unique nodes, edges, and evidence IDs;
- contain no self-loop or dangling graph edge;
- reference only existing evidence;
- have a non-empty selected path without repeated nodes;
- connect every consecutive selected-path node with a directed edge;
- start the selected path at a situation;
- end it at an outcome or lesson.

Invalid packs are excluded. Their bounded error summaries are stored only in the workflow evidence artifact, not in the public comment.

## Evidence artifact

Each attempt records:

- repository and pull-request number;
- exact head and base SHAs;
- accepted, publishable, withheld, and rejected counts;
- selected paths, pack IDs, source commits, scores, and matched terms;
- comment creation/update action and comment ID;
- duplicate managed-comment count;
- `direct_main_write: false`;
- `approval_authority: false`;
- `merge_authority: false`;
- `execution_authority: false`.

## Security boundary

`pull_request_target` is used only because a comment must be written reliably, including for fork pull requests. Its use is constrained:

- workflow and runtime come from the trusted default branch;
- checkout ref is the exact base SHA;
- source-branch code is never checked out or executed;
- no patch, diff, review body, issue comment, or prompt is ingested;
- no repository secret is used;
- persisted Git credentials are disabled;
- workflow permissions are limited to `contents: read`, `pull-requests: read`, and `issues: write`;
- runtime is stdlib-only;
- all API pagination and memory sizes are bounded;
- failures are fail-closed and produce an evidence artifact.

## Product boundary

Retrieval v0.1 answers:

> Which accepted prior decisions look relevant to this change, and what constraints must the reviewer re-check?

It does not claim semantic equivalence, causal proof, global optimality, or permission to reuse a past solution automatically.
