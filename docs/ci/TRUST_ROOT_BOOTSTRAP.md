# CML protected CI trust root

The normal pull-request workflows execute against the proposed commit. Their test
results are useful, but a pull request must not be able to weaken the validator
that certifies those same results.

`CML Trust Root Gate` therefore runs from the base branch through
`pull_request_target` and treats the pull-request checkout as data only. It never
executes pull-request code in a job with write permissions.

The gate verifies:

- the exact 40-character pull-request head SHA;
- exact Git blob identities for the approved CI, security, package, validator,
  package-init, and mutation-test files;
- independent SHA-256 observations for every protected file in the evidence;
- a complete local comparison of the checked-out base and subject trees, without
  relying on GitHub's capped pull-request-files API;
- absence of changes to `.github/trust-root/` and the trusted gate workflow;
- absence of new or unapproved workflow files;
- absence of root-level Python modules or packages that could shadow imports used
  by the protected CI helpers.

The evidence report records repository, pull request, exact head, workflow run ID,
and run attempt. Artifact names and the published status URL are also bound to the
exact run attempt, so reruns cannot silently reuse or obscure earlier evidence.

The gate publishes a branch-scoped commit status on the exact test-merge SHA,
not on the pull-request head. The separate publishing job never checks out or
executes pull-request content. Before publication it re-reads the PR and compares
its base ref, base SHA, head SHA, and test-merge SHA with the selected tuple. If
that tuple changed, it refuses to publish a stale status. Verification failures
still produce structured JSON evidence before the verification job exits non-zero.

The context is derived from the exact base-ref name encoded as UTF-8:

```python
"CML Trust Root Gate / " + hashlib.sha256(base_ref.encode("utf-8")).hexdigest()
```

For `main`, the exact context is:

```text
CML Trust Root Gate / 0d6e4079e36703ebd37c00722f5891d28b0e2811dc114b129215123adcce3605
```

Matching PR metadata across reads is a freshness check, not independent proof
that the selected base is the current branch tip or that the test-merge parents
match the selected base/head. Those stronger checks are not claimed here.

## Bootstrap boundary

Trust-root installation and maintenance are reviewed in the same pull request as
the implementation, using the normal PR review process. No separate bootstrap-review
PR, additional approval round, or extra human-and-bot sign-off is required. This
removes the additional procedural stage, not existing repository review settings,
automated review checks, or technical validation requirements.

The first installation still cannot be authenticated by the mechanism it introduces.
Each proposed trust-root transition must bind the protected CI implementation and
matching manifest identities to one exact tree; the candidate cannot certify itself.

After installation, the base-branch trust root remains authoritative. Changes to the
trusted gate, its manifest, or protected file identities that violate that baseline
remain rejected. Normal PR review does not override a failing gate, replace the
trusted base, or authorize a candidate to approve its own manifest. Removing the
separate review stage neither approves a new baseline nor authorizes a merge,
release, or package publication.

The verifier's historical diagnostic text may still mention a "dedicated bootstrap
review". That text reports a protected-path rejection; it is not a separate review
job or a reason to remove the rejection. The verifier and its acceptance conditions
are unchanged by this procedural update.

## Merge enforcement

Repository rules must require the exact branch-scoped context above for merges
to `main`, rather than the historical unsuffixed workflow name. The expected
status-source app must be verified and configured; accepting any source is not
equivalent to verifying the intended publisher. Required CI, package, and security
checks must also be retained as execution evidence.

These are configuration requirements, not a claim that protection is currently
enabled. Confirm the effective branch-protection and applicable ruleset settings
separately. A denied administrative read means that detailed configuration is
unverified; it must not be interpreted as an empty configuration. A red status
alone does not prove that GitHub prohibits a merge. Documentation edits and
ordinary PR review do not configure protection or authorize bypassing a failure.

The exact test-merge status, the current PR tuple, and the published run/attempt
must be checked together. Historical success on another head or merge SHA is not
a new verification. See GitHub's [required-status-check guidance](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
and [status-source configuration](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-status-checks-to-pass-before-merging).

The gate checks that protected definitions and authoritative validators match
the accepted baseline. Runtime CI success and authorization to change that
baseline remain distinct. This section adds no separate bootstrap-review stage.

## Security separation

The verification job has `contents: read` and `pull-requests: read`, with no
write permissions. It checks out the base and proposed commit into separate
directories and uses the proposed tree strictly as data. The status-publishing
job has `pull-requests: read` and `statuses: write`, never checks out proposed
content, and publishes success only when GitHub's `needs.verify.result` is
`success` and the selected PR transition still matches. A changed transition
produces no new status, not a successful verification.

This design prevents a pull request from replacing its own evidence validator,
adding a status-spoofing workflow, changing the trusted manifest, hiding a change
past an API pagination cap, or using Python import shadowing to alter the protected
helpers while retaining a trusted gate.
