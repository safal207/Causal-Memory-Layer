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

The final status is written to the pull-request head as `CML Trust Root Gate` by a
separate job that never checks out or executes pull-request content. Verification
failures still produce structured JSON evidence before the job exits non-zero.

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

Repository rules must require the `CML Trust Root Gate` status for merges to
`main`. Existing CI, package, and security checks remain required as execution
evidence; the trust-root gate proves that their definitions and authoritative
validators match the approved contract.

## Security separation

The verification job has only `contents: read`. It checks out the base and proposed
commit into separate directories and uses the proposed tree strictly as data. The
status-publishing job has `statuses: write`, never checks out proposed content, and
bases its result only on GitHub's `needs.verify.result`.

This design prevents a pull request from replacing its own evidence validator,
adding a status-spoofing workflow, changing the trusted manifest, hiding a change
past an API pagination cap, or using Python import shadowing to alter the protected
helpers while retaining a trusted gate.
