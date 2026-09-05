# CML Memory Retrieval v0.1.1

CML Memory Retrieval surfaces relevant **accepted** engineering memory while a pull request is under review.

```text
merged pull request
→ reviewed Memory Pack proposal
→ accepted memory on main
→ new pull request
→ relevant accepted memory comment
```

The comment is advisory. It cannot approve, execute, modify, or merge code.

## GitHub lifecycle

The protected workflow runs only from `pull_request_target` for pull requests targeting `main` on these events:

- opened;
- reopened;
- synchronized;
- edited;
- marked ready for review.

There is no manual-dispatch path. The workflow checks out and executes only the exact pull-request base SHA. Source-branch code, patches, diffs, review comments, issue comments, and prompts are never executed or ingested.

The job token has only:

```text
contents: read
pull-requests: write
```

`pull-requests: write` is used solely to list, create, update, delete, and reconcile the managed PR comment. The workflow has no content-write, Actions-write, approval, direct-main, execution, or merge authority.

## Retrieval

Version 0.1.1 uses deterministic Unicode lexical retrieval rather than embeddings or a language model.

Query weights:

| Pull-request field | Weight |
|---|---:|
| title | 4 |
| changed filenames | 3 |
| body | 1 |

Memory-node weights:

| Node | Weight |
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

Ranking uses corpus-level inverse document frequency and cosine similarity. Results need at least two shared meaningful terms and must pass the minimum score. Ties are resolved by exact `pack_id` and path. At most three results are shown.

## Accepted-memory validation

Every candidate must:

- use `cml-memory-pack-v1`;
- contain only exact known fields;
- have a canonical SHA-256 `pack_id`;
- bind to the current repository and a full source commit;
- grant neither merge nor execution authority;
- contain unique nodes, edges, and evidence IDs;
- contain no self-loop or dangling edge;
- reference only existing evidence;
- have a connected selected path from situation to outcome or lesson.

Invalid packs are excluded.

## Privacy

Privacy is applied before ranking and again before comment or artifact output.

In a public repository, only packs satisfying both conditions are publishable:

```text
visibility = public
contains_private_data = false
```

Public and internal comments and artifacts do not reveal accepted non-public counts, withheld counts, invalid counts, rejected paths, validation details, or exception text. They may show only publishable candidates and selected publishable evidence.

Private repositories may retain bounded repository-local diagnostics inside the private access boundary.

## Managed comment

The marker is:

```html
<!-- cml-retrieval-v0.1 -->
```

Only a comment authored by `github-actions[bot]` with that marker may be updated or deleted. Human comments containing the marker are untouched.

The upsert is fail closed:

1. create or update the oldest bot-authored managed comment;
2. list comments again;
3. delete extra bot-authored managed comments;
4. verify that exactly one canonical comment remains with the expected body.

Any create, update, delete, or postcondition failure fails the workflow.

## Evidence and failure stages

Every attempt records non-sensitive operational facts, including exact head/base SHAs, selected publishable packs, managed-comment action, canonical comment ID, duplicate count, and explicit false authority fields.

A failed attempt uses a generic message and may expose only one allowlisted phase:

```text
repository-bind | event-read | event-bind | runtime
pull-api | pull-validate | files-api | repository-api
corpus-load | query-rank | comment-render
comment-list | comment-create | comment-update
comment-delete | comment-verify
```

Exception text, API response bodies, private paths, rejected-pack details, and attacker-controlled stage values are not emitted. Unknown stage values are replaced with an allowlisted fallback. Successful evidence carries `failure_stage: null`.

## Product boundary

Retrieval answers:

> Which accepted prior decisions look relevant to this change, and what constraints must the reviewer re-check?

It does not claim semantic equivalence, causal proof, global optimality, or permission to reuse a past solution automatically.
