# Reviewer B protected PRIVATE read preflight — staged privileged PR

**DRAFT PROPOSAL — not deployed, NOT a live security review.**

This follow-up PR is intentionally separate from the secret-free public
Publisher prototype PR #2. Do NOT merge it into protected `main` until
the public Publisher is independently reviewed, the no-secret approval
environment has passed a real hold-and-release test, and this privileged
workflow itself passes an exact-HEAD security review.

## Exact privileges and boundaries

- Workflow: `.github/workflows/reviewer-b-private-readonly-preflight.yml`.
- Trigger: manual `workflow_dispatch` only. Job runs ONLY for
  `devfactory-reviewer-service` actor, repo
  `devfactory-reviewer-trust/devfactory-reviewer-b-publisher`, protected
  `refs/heads/main` and the pre-existing `reviewer-b-publish` environment.
- GitHub GITHUB_TOKEN: `contents: read` in the PUBLIC Publisher, used solely
  to fetch the immutable triggering protected `github.sha` source tarball.
  It has no PR/Issue write, OIDC mint, attestation write or merge right.
- Environment secret: **one** protected GitHub App JWT PEM,
  `REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM`. It must be created only after
  the workflow and security gates are reviewed; never commit it, paste it
  into ChatGPT, or place it on the DevFactory MSI.
- The App token is constrained to exact PRIVATE repository ID 1282086207,
  `Contents: read` + `Pull requests: read`, without Issues or PR write.
  App ID and installation ID from historical owner state must be reverified
  in GitHub settings before provisioning a key.
- A user-supplied PR number is passed as an ENVIRONMENT VARIABLE, not
  interpolated into shell text. Runtime accepts only a positive decimal
  integer and an open non-draft PR on private `master`.
- The diff is read at immutable BASE/HEAD. The output prints only a
  bounded result label (`INCONCLUSIVE_NOT_REVIEWED`,
  `STATIC_FINDINGS_BLOCK`, `CREDENTIAL_NOT_PROVISIONED` or a generic
  safe failure). PRIVATE source and report bytes are not logged.
- No model inference, native GitHub REVIEW, GitHub merge, HUMAN_GO creation,
  external witness, change to branch protection or credentials write.

## Mandatory manual ceremony after protected merge

1. Verify branch protection of Publisher `main` and the actual
   `reviewer-b-publish` required approvers (prevent self-review, no bypass).
2. Independently review this PR's exact source and execute **offline**
   synthetic negative tests. Do not confuse Gemini COMMENTED with sign-off.
3. Approve `Contents:Read` in the existing GitHub Reviewer B App for the
   one private `deenkids7-dev/deenkids` repo. Confirm installation ID.
4. Only then provision the new App private PEM in the protected environment;
   never copy to any public artifact or log.
5. Dispatch this *specific* workflow on `main` as
   `devfactory-reviewer-service` with a non-draft private test PR number.
   The job must WAIT for manual environment approval by
   `deenkids7-dev`; verify the held approval and exact run actor.
6. Confirm stdout reports only a non-PASS bounded status, verify actual
   private source read via protected self-contained diagnostics, and inspect
   GitHub App token API audit/permission records without exposing private
   source.
7. **STOP**: before review publication, a separately signed and verified
   report, semantic reviewer quality/provenance, durable nonce/replay
   prevention, native review-ID readback and canonical HUMAN_GO remain
   necessary. This workflow alone never removes the last Reviewer B gate.

No third account, CodeRabbit, monthly AI subscription, second scheduler,
second state ledger or competing merge authority is introduced.
