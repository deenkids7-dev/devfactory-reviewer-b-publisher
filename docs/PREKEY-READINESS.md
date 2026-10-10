# Pre-key readiness and operator ceremony — 2026-10-10

**STATUS: KEYS MUST NOT BE CREATED OR PROVISIONED YET.**

This is a security runbook, not permission to publish or merge. The Publisher
repository is PUBLIC and protected; private source, private GitHub App keys,
and private review reports must never be committed, placed in PR artifacts,
or emitted to public Actions logs.

## Verified / reported infrastructure

- Organization-owned public publisher (not independent human ownership):
  `devfactory-reviewer-trust/devfactory-reviewer-b-publisher`.
- `devfactory-reviewer-service`: authenticated writer/organization owner.
- `deenkids7-dev`: organization Member, repository READ-only confirmed.
- Publisher `main`: protected, CI names
  `Verify independent runner` and
  `Verify fail-closed attestation logic`. Owner reported both required;
  detailed branch protection API inaccessible with this connector (HTTP 403).
- Environment `reviewer-b-publish`: owner reported it saved with
  `deenkids7-dev` as sole required reviewer, prevent self-review ON,
  administrator bypass OFF, only protected branches.
  **No verified approval hold-and-release execution yet.**
- Public test runners: NO production secrets, NO native reviews, NO model,
  NO `workflow_run`, `pull_request_target` or privileged write grants.
- Candidate modules in `candidate/` are dormant; their tests use synthetic
  GitHub responses and ephemeral keys only.

## Trust boundaries and independent key roles

1. **App JWT RSA key** (owner: `deenkids7-dev`): the existing GitHub App
   `DevFactory Reviewer B`, App ID `5253138` from owner UI; installation
   ID `169674558` from historical state (REVERIFY on actual App settings).
   The installation must remain scoped to private
   `deenkids7-dev/deenkids`. Historically it has Metadata: Read and
   Pull requests: Read/Write. An immutable compare/{base}...{head} diff of
   this PRIVATE repo ALSO requires **Contents: Read**, which is NOT YET
   approved or configured. The protected reviewer will request a separately
   downscoped read token (Contents: Read, Pull requests: Read) distinct from
   the publish token (Pull requests: Write, no Contents access). NEVER grant
   Contents: Write. GitHub generates the App JWT private key; it must be
   provisioned to a
   protected environment **only after workflow security audit and successful
   secret-free environment hold test**. Never give it to MSI or ChatGPT.
2. **Native review-marker RSA signing key**: independently generated RSA
   key pair (2048-bit MIN, preferably 3072-bit) DISTINCT from App JWT key.
   Corresponding RSA SPKI SHA-256 must be pinned in a separate trusted
   configuration consumed by draft DevFactory PR #900. Do not generate or
   pin until the signed protocol is independently reviewed at exact PR HEAD.
3. **Analyzer Ed25519 key**: belongs to a genuinely separate reviewer engine
   execution/trust domain; never store its private key alongside the
   Publisher's JWT/native RSA secrets. The publisher receives only the
   analyzer public SPKI fingerprint and signed evidence. The model provider
   credentials (if needed) must also remain within this independent engine,
   not on MSI.

A key signature proves possession of a key, not analyzer independence,
correctness, or permission to APPROVE. All positive fixtures must remain
synthetic until the independently witnessed runtime is implemented.

## Remaining tasks that can proceed WITHOUT private keys

- [x] Read-only GitHub API adapter, scoped to one repository and PR selector.
- [x] Text-diff consistency and SHA-256 binding (synthetic API tests).
- [x] Fail-only static analysis; reports never contain raw added code lines.
- [x] Model-output schema normalization: a "no findings" response is
      INCONCLUSIVE, never automatically PASS.
- [x] DeepSeek Flash pure request/response budget and schema candidate,
      synthetic model provenance, deterministic model-finding fingerprints
      and full offline signing/test rehearsal. NO live API call.

- [x] Ed25519 and RSA formatting/verification using synthetic keys.
- [x] GitHub App JWT and downscoped installation-token request **simulation**.
- [x] GitHub native reviews GET + duplicate reviewer protections (synthetic).
- [x] Source-independent regression tests for candidate trust boundaries.
- [ ] Independent security review of Publisher PR #2 on its exact HEAD.
- [x] Prepared a zero-credential, manual-only environment probe workflow
      `.github/workflows/reviewer-b-environment-hold-probe.yml` on PR #2.
      It cannot execute from the protected default branch until an
      independently reviewed merge occurs. This is NOT a completed gate.
- [ ] Validate GitHub environment hold-and-release on protected `main`
      **using a zero-secret, zero-diff workflow** (cannot simply rely on
      the Settings screenshot).
- [ ] Choose an actual independent semantic reviewer; validate reviewer
      quality, runtime identity/provenance and full isolation from MSI.
- [ ] Choose a provider cost cap, or offline inference engine on a hosted
      runner, with explicit approval before any charges.
- [ ] Implement a separately verified external provenance witness bound to
      exact PR/HEAD/BASE/report/GitHub review ID.
- [ ] Independently approve GitHub App **Contents: Read** to fetch an
      immutable private commit comparison. GitHub REST Compare two commits
      documents this mandatory permission. The App DOES NOT have it yet.
      Do not grant Contents: Write. The split purpose-bound tokens in
      candidate/github-app-auth.mjs remain synthetic pending authorization.
      https://docs.github.com/en/rest/commits/commits#compare-two-commits
- [ ] Independently approve minimum GitHub App Issues:Read (if used) for
      canonical Issue/LOT metadata; present App has Metadata Read and Pull
      requests Read/Write only. Do not permit Issues Write.
      See `docs/HUMAN-GO-INTEGRATION-BOUNDARY.md`.
- [ ] Integrate with existing canonical DevFactory HUMAN_GO mechanism;
      secrets and destructive DB operations remain special human-only gates.
- [ ] Implement a protected publication workflow from independently reviewed
      `main`: no untrusted PR checkout, no secret access on PR CI, exact
      trusted code SHA, serialized PR processing, authoritative native review
      evidence, mandatory immediate HEAD recheck.
- [ ] Cross-test against current draft DevFactory PR #900 adapter at exact
      HEAD; no self-declared PASS, no fallback from missing provenance.
- [ ] Prove recovery/idempotence, auditability and rotation before any live
      native review or PR merge.

## Required operator involvement when those tasks are ready

This sequence cannot safely be collapsed into a blind one-time permission:

1. Independently approve reviewed protection/probe workflow and deploy only
   that NO-SECRETS workflow to protected `main`.
2. From the service account, trigger its no-secret environment deployment.
   From the distinct `deenkids7-dev` account, approve the pending environment
   job. Confirm it remained held until the distinct approver authorized it.
   This operator authorization is NOT a technical independent code review.
3. Independently review the finished secret-bearing workflow, isolated
   analyzer trust/provenance and expected DevFactory PR #900 contract.
4. Approve a strict zero-surprise spending limit / offline model selection.
5. **Only then** create/provision each distinct key within its actual trust
   boundary; supply ONLY PUBLIC fingerprints through trusted channels.
6. Grant canonical `HUMAN_GO` for a concrete PR and exact HEAD only.
   No merge, production access, provider spend or privileged operation before
   the existing DevFactory authority permits it.

Stop if any one step fails. Never paste key PEM, PAT, token, private GitHub
source, or paid-provider credentials in ChatGPT, a GitHub issue, repository
files, Actions logs or public artifacts.

## No secret-bearing workflow exists in this PR

A `candidate/` module does NOT establish deployment readiness. Passing
tests means only that synthetic contracts and fail-closed behavior passed.
No production App installation JWT, native RSA signature, Ed25519 independent
analyzer attestation, genuine review, or GitHub APPROVED review has occurred.

## Current pre-key blocker (must not bypass)

The source-level candidate and the no-secret environment probe are on
**DRAFT Publisher PR #2**, not the protected `main`. The separate operator
reviewer can only approve an environment deployment after its workflow has
been independently audited and reached protected `main` by an authorized PR
merge. No independent external provenance engine or real semantic model has
been provisioned. The required action is therefore **security review and
approval of a safe promotion**, NOT generation of a private key today.
