# CML Memory Learning Loop

The CML Memory Learning Loop converts an eligible merged pull request into a **reviewable memory proposal**. It does not silently teach the repository and it never writes accepted memory directly to `main`.

## Lifecycle

```text
pull request merged into main
        ↓
protected learning workflow
        ↓
normalize PR, files, reviews, and exact-head checks
        ↓
construct deterministic team-only Memory Pack
        ↓
create cml-learning/... branch
        ↓
open draft memory PR
        ↓
explicitly dispatch CI, package, and security validation
        ↓
maintainer reviews proposed graph and lesson
        ├── merge → memory accepted
        └── close → memory rejected
```

The generated PR itself is excluded from the learning loop, preventing an infinite sequence of memory-about-memory proposals.

## Trigger modes

The protected workflow supports:

- automatic execution after a pull request is merged into `main`;
- manual `workflow_dispatch` with a merged pull-request number for backfill or live validation.

A manual run uses the current protected implementation from `main`. It does not execute code from the source pull-request branch.

## Trust boundary

The write-capable runtime lives under:

```text
.github/trust-root/scripts/
```

It is stdlib-only and split into three protected components:

- `memory_learning_core.py` — pure normalization and Memory Pack construction;
- `memory_learning_github.py` — bounded GitHub API adapter and proposal state machine;
- `memory_learning_loop.py` — small CLI entrypoint and evidence writer.

The workflow checks out the merged default-branch commit with persisted Git credentials disabled. Ordinary pull requests cannot alter the workflow or runtime without an explicit trust-root bootstrap review.

## Generated memory semantics

Every automatic proposal defaults to:

```json
{
  "visibility": "team",
  "contains_private_data": true,
  "merge_authority": false,
  "execution_authority": false
}
```

The generated lesson node has:

```json
{
  "status": "proposed",
  "confidence": 75,
  "attributes": {
    "generated": true,
    "human_review_required": true,
    "globally_optimal": false
  }
}
```

This prevents a successful merge from being misrepresented as universal causal truth. A maintainer must review the graph, amend incorrect interpretation, remove sensitive material, and decide whether the lesson should be accepted.

## Extraction policy

The loop uses explicit Markdown sections when they are present:

- `Summary`, `Purpose`, or `Goal` → situation;
- `Root cause`, `Problem`, or `Context` → cause;
- `Design`, `Changes`, `Implementation`, or `Solution` → action;
- `Validation`, `Verification`, or `Testing` → check;
- `Boundary`, `Limitation`, `Non-claim`, or `Scope` → constraint.

A cause node is created only when an explicit cause-like section exists. The system does not invent a root cause from the title or diff.

When optional sections are missing, the loop emits conservative fallback action, check, constraint, and lesson text marked as generated.

## Evidence policy

The pack stores SHA-256 digests of normalized snapshots for:

- pull-request metadata and body;
- changed-file metadata;
- review metadata without review bodies;
- exact-head check-run metadata;
- merge commit identity.

Raw event payloads and review bodies are deliberately excluded. This reduces accidental disclosure and prevents untrusted review prose from being carried into future agent prompts.

The digests establish deterministic integrity of the normalized snapshots. They do not prove that GitHub data is truthful, independent, complete, or permanently available.

## Idempotency and recovery

The proposal identity is derived from the source pull-request number and merge SHA:

```text
branch: cml-learning/pr-<number>-<merge-sha-prefix>
file:   .cml/memory/cycles/pr-<number>-<merge-sha-prefix>.json
```

Repeated delivery behaves as follows:

- memory already exists on `main` → accepted no-op;
- matching proposal PR is open → no duplicate PR; validations are re-dispatched;
- matching proposal PR is closed → rejected no-op;
- branch exists with the exact expected pack → resume PR creation;
- branch exists with different content or an unexpected ref → fail closed.

The workflow never force-updates a generated branch.

## Validation dispatch

Pull requests created with the repository `GITHUB_TOKEN` do not reliably trigger downstream workflows through ordinary event chaining. After opening a memory proposal, the loop explicitly dispatches:

- `ci.yml`;
- `python-package-validation.yml`;
- `security.yml`.

All three run against the generated branch ref.

## Evidence artifact

Every learning-loop attempt uploads an exact-run/exact-attempt evidence artifact recording:

- source pull-request number;
- outcome and skip reason;
- proposed memory path and pack ID;
- generated branch and proposal PR;
- dispatched validation workflows;
- `direct_main_write: false`;
- `merge_authority: false`;
- `execution_authority: false`.

## Known limitation

The automatic `pull_request` trigger depends on the permissions GitHub grants to the event. Merges from restricted fork contexts may fail closed if the token cannot create a branch or PR. A maintainer can use the manual backfill mode after the merge from the protected default branch.
