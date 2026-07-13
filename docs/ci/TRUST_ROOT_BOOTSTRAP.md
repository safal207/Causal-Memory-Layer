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
- absence of changes to `.github/trust-root/` and the trusted gate workflow;
- absence of new or unapproved workflow files;
- absence of root-level Python modules or packages that could shadow imports used
  by the protected CI helpers.

The final status is written to the pull-request head as `CML Trust Root Gate` by a
separate job that never checks out or executes pull-request content.

## Bootstrap boundary

The first pull request that installs this trust root cannot be authenticated by
the mechanism it is introducing. It requires explicit human and independent bot
review. After it lands on the protected default branch, ordinary pull requests
are checked by the base-branch trust root.

Changes to the trusted gate, its manifest, or approved file identities require a
dedicated bootstrap review. They cannot be approved by an ordinary pull request.

Repository rules must require the `CML Trust Root Gate` status for merges to
`main`. Existing CI, package, and security checks remain required as execution
evidence; the trust-root gate proves that their definitions and authoritative
validators match the approved contract.

## Security separation

The verification job has only `contents: read` and `pull-requests: read`. It
checks out the proposed commit but uses it strictly as data. The status-publishing
job has `statuses: write`, never checks out proposed content, and bases its result
only on GitHub's `needs.verify.result`.

This design prevents a pull request from replacing its own evidence validator,
adding a status-spoofing workflow, changing the trusted manifest, or using Python
import shadowing to alter the protected helpers while retaining a trusted gate.
