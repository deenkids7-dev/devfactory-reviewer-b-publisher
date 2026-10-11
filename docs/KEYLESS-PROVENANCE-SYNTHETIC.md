# Keyless provenance: public synthetic preflight only

## Why this exists

The current Reviewer B blocker is NOT a lack of unit tests: native review,
report, and signatures cannot prove who actually executed the independent
review. GitHub-hosted Actions plus Sigstore can establish **execution
provenance** without adding a GitHub account or a paid inference provider.
They do not establish human independence or semantic review correctness.

The Publisher repository is PUBLIC. GitHub's artifact attestation feature is
available on current free plans for public repositories. This is deliberately
not an attempt to generate attestation in the PRIVATE DevFactory repository,
where free-plan artifact attestations are unavailable.

## Implemented safe rehearsal

`.github/workflows/reviewer-b-keyless-synthetic-proof.yml` is an
protected-main-only, environment-held workflow with manual dispatch and a narrowly
scoped one-time marker-filtered push activation.
It uses a GitHub-hosted runner, creates ONE fixed PUBLIC synthetic JSON subject
and calls the pinned GitHub-maintained `actions/attest` action. Permissions
are limited to `id-token: write` and `attestations: write`. The workflow's
`create-storage-record: false` only disables optional linked-artifact
metadata: it does **not** disable upload of the signed attestation to the
GitHub attestation API. No private source is checked out, no API source diff is
fetched, no App/PAT/model key is
required, no review is posted, and no approval/merge is authorized.

The workflow is **not executable from a PR branch**. The one-time push trigger
is restricted to the exact public synthetic retry marker path; it
requires the approved service-account actor and a separate protected
environment approval. It cannot retrieve or attest private source. It must first pass
review/authorization, be merged to protected `main`, and pass the existing
`reviewer-b-publish` environment hold-and-release gate. Branch protections
and required CI checks remain intact. The organization's GitHub Actions policy
must independently allow the exact pinned GitHub-authored action; do NOT allow
arbitrary actions just for this test.

Once authorized and deployed, operator can dispatch manually from
`devfactory-reviewer-service`, approve the held environment only from its
configured approver account, and audit the run, workflow source commit, job
logs and attestation ID. GitHub's external signature verifies *where the public
synthetic subject was attested*, not that real Reviewer B ran.

To reconstitute the public subject byte-for-byte for an authorized
post-run verification on a trusted local machine, first read the **actual**
`github.sha` from the successful approved workflow run on protected
`main`. Supply that verified commit as `PUBLISHER_MAIN_SHA`. Never choose
the current default-branch HEAD or accept a commit from the PR branch:
a later run could have a different signing source. The GitHub CLI must
validate the certificate provenance, not merely the untrusted statement.

```sh
# Replace with the exact 40-hex SHA recorded on the approved protected-main run.
PUBLISHER_MAIN_SHA='REPLACE_WITH_VERIFIED_40_HEX_RUN_SHA'
[[ "$PUBLISHER_MAIN_SHA" =~ ^[a-f0-9]{40}$ ]] || exit 1
printf '%s\n' '{"schema":"devfactory.synthetic-provenance.v1","not_a_review":true,"private_code":false}' > reviewer-b-synthetic-proof.json
gh attestation verify reviewer-b-synthetic-proof.json \
  -R devfactory-reviewer-trust/devfactory-reviewer-b-publisher \
  --signer-workflow devfactory-reviewer-trust/devfactory-reviewer-b-publisher/.github/workflows/reviewer-b-keyless-synthetic-proof.yml \
  --signer-digest "$PUBLISHER_MAIN_SHA" \
  --source-ref refs/heads/main \
  --source-digest "$PUBLISHER_MAIN_SHA" \
  --deny-self-hosted-runners
```

This verification can only succeed if a REAL matching attestation has been
published. It must never be mocked as a source of live authority.

## Hard stop before real private PR review

- A published public synthetic attestation is NOT a Reviewer B PASS.
- A real semantic analyzer still must read the target PRIVATE PR using a
  separately downscoped GitHub App Contents:read permission; it must be
  isolated from the code author and have independently checked execution.
- Private code, model inputs, static findings, report bodies, credentials and
  signing keys must never enter PUBLIC Publisher source, logs or artifacts.
- The existing native Reviewer B adapter in DevFactory PR #900 requires
  independently trusted signing and post-review witness of the exact GitHub
  review ID, PR, HEAD, BASE, report digest, and run. This probe provides none
  of those real bindings.
- Enabling a GitHub-attested **automated-review** approval policy in lieu of
  external-human security review is an explicit governance change, not an
  innocuous interpretation of current evidence. It requires a separately
  reviewed policy change, exact GitHub HUMAN_GO and end-to-end negative tests.
  Do not silently promote this probe to security reviewer authority.
- Until these gates exist, keep PR #2/#3 and private #898/#899/#900/#901
  unmerged.

No new scheduler, state ledger, Merge Executor, reviewer account, paid API or
CodeRabbit dependency is introduced.
