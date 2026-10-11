# Independent Reviewer B Publisher security review request

**Status: SECURITY REVIEW REQUESTED — NOT APPROVED.**
This document is an aid for a genuinely independent reviewer of PUBLIC
Publisher draft PR #2. It does not claim independence, PASS or authority.

## Exact objects to examine

- Public repository: `devfactory-reviewer-trust/devfactory-reviewer-b-publisher`
- PR: https://github.com/devfactory-reviewer-trust/devfactory-reviewer-b-publisher/pull/2
- Base: protected `main`; do not bypass required status checks.
- Current HEAD: obtain freshly from GitHub; do not rely on a stale SHA
  recorded in a comment or this document.
- Private target repository: `deenkids7-dev/deenkids`
- Private target adapter: draft PR #900, NOT merged or production-authoritative.
- Proposed environment: `reviewer-b-publish`, operator approver
  `deenkids7-dev` (configured in GitHub UI but hold/release untested).
- App: `DevFactory Reviewer B`, App ID `5253138` (owner UI),
  installation ID `169674558` (historical; reverify before any key).

## Threat model

The Publisher repository is PUBLIC. The DevFactory repository is PRIVATE.
The separate Publisher account has code write permission; the MSI's
primary GitHub identity has Publisher read-only. The same human controls
both accounts; therefore a deployment approval is NOT an independent code
or execution-provenance review. Assume every PR body, changed source line,
model answer, report attachment, fork or GitHub issue comment is untrusted.
Assume attacker can manipulate any code they author, their diff, the PR
description and all untrusted artifacts. No signed metadata may be taken
as evidence of the actual independence of its origin.

Secrets that must NEVER enter public workflow jobs, logs or artifacts:
private GitHub App JWT key, short-lived installation token, separate
native RSA signing key, independent analyzer Ed25519 key, provider API
credentials, full private diffs, private Issue/LOT content.

## Technical checks for the independent reviewer

1. **No production path**: inspect every `candidate/`, `src/`, entrypoint,
   dependency and workflow. Verify no action publishes `APPROVE`,
   `REQUEST_CHANGES`, posts a review, merges a PR or obtains live secrets.
   Green synthetic CI is not proof of independence.
2. **Workflow trust**: require PR CI to run with read-only `GITHUB_TOKEN`
   and without `pull_request_target`, `workflow_run`, OIDC, private key,
   checkout of untrusted code in a privileged context or external POST.
3. **Deployment hold probe**: review
   `.github/workflows/reviewer-b-environment-hold-probe.yml`.
   It must be manual-only, scope to protected `main`, with
   `permissions: {}`, no secrets and no network. It MUST NOT be executed
   or treated as proof while it exists only on a draft PR.
4. **Private source boundary**: audit all transport error paths,
   response type/size caps, redirect prohibitions, token handling, logging,
   model-input construction and serialization. No private diffs, code lines
   or bearer tokens may appear in PUBLIC Actions output.
5. **PR identity**: verify repository ID `1282086207`, original owner,
   current HEAD+BASE, path and hunk completeness, changed file coverage,
   text/binary and fork handling. Changed HEAD must fail closed.
6. **Signer boundaries**: check the three distinct identities
   (GitHub App RSA JWT, native RSA review marker, analyzer Ed25519),
   public-key SPKI SHA-256 pinning, noncanonical/duplicate JSON rejection,
   replay and nonce design. Do not reuse any key.
7. **Native adapter compatibility**: reconcile fields, sorting codec,
   base64url marker, report bytes, review bot ID/login, installation ID,
   timestamps and review state against PRIVATE PR #900 **at its live HEAD**.
   No "PASS" may come from a claimed signature without separate
   authenticated execution provenance and canonical HUMAN_GO.
8. **Human clearance**: do not create an additional controller, State
   Ledger, audit engine, model router or alternative approval authority.
   The existing Issues/LOT HUMAN_GO policy is authoritative.
9. **Race/idempotency**: native reviews must be read fresh, HEAD rechecked
   immediately before write, bot reviews deduplicated. A future publisher
   must serialize per PR, persist an authoritative single-use nonce and
   confirm assigned GitHub review ID after POST.
10. **Model quality**: static matching cannot establish PASS. Public
   synthetic Ollama/Qwen runs exist; no authorized PRIVATE-code reviewer
   engine or independent witness is installed. A model-generated clean
   report is only INCONCLUSIVE in the current candidate. Real review
   quality, model deployment and credential separation need further audit.

## External CodeRabbit review on an older commit (NOT approval)

CodeRabbit submitted GitHub review 5478886673 on 2026-10-10 at
`906c79cf387b517af26710a9edffbca7607fe122` with status COMMENTED
and 13 inline findings, including a MAJOR immutable-diff/HEAD TOCTOU
concern. This is real external review feedback, not an APPROVED review
of the latest HEAD. The subsequent source uses immutable
`compare/{base_sha}...{head_sha}` plus before/after PR metadata, and
tests require that exact immutable endpoint. GitHub's documented
`Contents: Read` permission is a mandatory still-unmet operator gate
before using it on a private repository. Do not treat previous CodeRabbit
feedback or green synthetic tests as complete current-HEAD security
clearance; request a NEW external review after code stabilizes.

## Known blockers and limitations (not PASS)

- No independent security review that covers the CURRENT PR #2 HEAD.
- Public synthetic Ollama inference has run, but there is still NO
  authorized independent PRIVATE-code analyzer, isolated trusted production
  reviewer, or authenticated independent execution provenance witness.
- No live privileged Publisher, approved publish policy or GitHub review
  POST; no native GitHub review has been published.
- No access to canonical private Issues through a separately scoped
  GitHub App Issues:Read token; scope change needs explicit operator consent.
- No Contents:Read on the private GitHub App installation yet; immutable
  compare endpoint will not work without independently approved scope.
- No live no-secret environment hold-and-release test yet.
- No protected secret-bearing `main` job/security review.
- No real private keys provisioned; all existing tests use synthetic
  fixtures and ephemeral keys.
- Text-only small diffs supported. Renames, binary patches, unsupported
  paths, altered/forked source repo or PR diff truncation are blocked.
- The public Publisher's code owner still controls organization settings.
  Environment review is separation of operational accounts only, not
  independence from the human owner.
- The proposed private PR #900 adapter is itself unmerged and must be
  tested against exact current code before accepting any live attestation.

## Decision form for an independent reviewer

The reviewer should record: their identity and independence from the
Publisher code author; exact commit SHA; verified source files, workflow
permissions and branch/env rules; concrete findings with file+line;
evidence for any claimed trusted engine/external witness; CI run IDs;
required remediations; and an explicit final recommendation.

A review may say `SECURITY REVIEW FAILED`, `CHANGES REQUIRED` or
`CODE REVIEW PASSED FOR NO-SECRET PROBE ONLY`. It must NEVER say
"production Publisher approved" until **all** protected trust gates
exist and have been validated, even if unit tests pass.

## Operator-controlled next stage

A genuinely independent qualified reviewer must first review the exact
PR changes or, preferably, a narrowly scoped no-secret-probe-only PR
created under the existing branch protection policy. A human operator
must authorize any protected merge; only after that may the environment
hold/release be observed. Later, an independently reviewed privileged
workflow plus real analyzer/provenance are required before creating keys.

**STOP: NO KEY GENERATION, PAID API ACTIVATION OR PRIVATE PR MERGE YET.**

## Independent review still pending — evidence as of 2026-10-10

The prototype now includes a pure external-account review-candidate filter
in candidate/independent-review-candidates.mjs with regression tests. It
rejects the co-owned service/DevFactory accounts, bots, stale HEAD review,
and superseded approvals. This filter NEVER reports independent security
review verified. There is still no GitHub APPROVED review by an externally
qualified independent reviewer of the current Publisher PR #2 HEAD.

A supplemental public CodeQL attempt failed at GitHub workflow startup
(run 38063996156, no worker/SARIF); it was removed. Actual CodeQL default
setup must be enabled in GitHub Repository Settings by an authorized admin,
then its results verified on the exact latest HEAD. Do not confuse this
with the separate third-party human security audit requirement.

The review cannot legitimately be completed by the PR author signing their
own work, using a co-owned GitHub account, relabeling model outputs as PASS,
or manufacturing evidence from a synthetic fixture. No Publisher or private
DevFactory PR merge, privileged key, app-scope escalation or production
review publication is authorized by the current record.
