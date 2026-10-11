# DevFactory Reviewer B — AUTOMATED_ATTESTED review policy proposal v1

**OPERATOR DIRECTION: YES to developing this mode, received 2026-10-11.**
**EFFECTIVE STATUS: PROPOSAL ONLY; no protected code rule is changed.**

## Decision and security boundary

Use the TWO existing GitHub accounts, the existing Reviewer B GitHub App,
public Publisher repository, free GitHub-hosted Actions, and a free or
explicitly pre-approved inference engine. Do not add a third account,
CodeRabbit, a second scheduler, a second merge executor, or a parallel
HUMAN_GO authority. No implicit ongoing fee, billing account activation or
private code transfer to Gemini without explicit budget/data approval.

`AUTOMATED_ATTESTED` and `INDEPENDENT_HUMAN` are **distinct evidence
classes**, never aliases. An attested GitHub execution is **not independent
human source review**. Formal authorization of this alternative requires
reviewed changes in both Publisher and private DevFactory admission/merge
policy plus canonical HUMAN_GO for any privileged migration. This document
must not be used as a new permission source or self-approved security pass.

## Authentic evidence path (design, NOT yet deployed)

1. A reviewed workflow under protected PUBLIC Publisher `main` requests
   a protected `reviewer-b-publish` environment release for a specific
   approved PR/HEAD. Never execute untrusted PR-branch code with secrets.
2. A downscoped installation token securely fetches PRIVATE
   `deenkids7-dev/deenkids` PR metadata twice and immutable
   `compare/{base}...{head}` diff. Compare raw SHA-256, exact repo
   ID=1282086207, PR, branch, HEAD, BASE; reject moves and unsupported diffs.
3. A separately authenticated analysis engine produces bounded findings.
   Independent Semgrep CE static checks cannot be erased by model output.
   A clean/no-findings model report remains **INCONCLUSIVE** until an
   explicitly defined quality and policy gate is satisfied.
4. Generate a **minimal canonical subject** containing the exact private
   target IDs and digests, report SHA-256, reviewer run ID, declared engine,
   analyzer-code digest and protected Publisher workflow source SHA.
   `candidate/keyless-review-binding.mjs` implements the byte-level
   subject builder and comparator **only**, with no approval path.
5. Inside the protected workflow, call GitHub's pinned `actions/attest`
   on subject bytes. Never submit the private diff, private model output,
   findings text, secrets or report bytes to PUBLIC artifacts/logs.
6. An independently authenticated verifier runs
   `gh attestation verify` with **exact** Publisher repo, signer workflow,
   signer digest, protected source ref and source digest; verify the subject
   digest *and* certificate OIDC identity. Do not trust unverified
   `statement.predicate` alone. The trust root must be reviewed and pinned,
   and execution of the verified workflow must not be writable by PR authors.
7. The final privileged Publisher re-checks HEAD and canonical GitHub
   HUMAN_GO, durable nonce/review-ID replay prevention, permissions and
   negative findings before selecting ANY native GitHub review event.
   A Publisher write-token must have no Contents:Read. A different private
   GitHub App key must not be reused as the native RSA marker-signing key.
8. DevFactory native Reviewer B adapter has to gain an **explicit,
   independently reviewed `AUTOMATED_ATTESTED` admission path** before
   this evidence may authorize a merge. Current PR #900 continues to require
   independently signed Ed25519 witness. Never reinterpret that contract.
   Elevated-risk changes retain manual HUMAN_GO and any specialized review.

## Mandatory fail-closed matrix

| Condition | Result |
| --- | --- |
| Synthetic attestation only | BLOCKED; not a review |
| GitHub Actions CI PASS only | BLOCKED; no Reviewer B result |
| Gemini COMMENTED or author-owned GitHub APPROVED | BLOCKED |
| Attestation no valid signer/ref/source digest | BLOCKED |
| Attestation correct but private HEAD, BASE or report changed | BLOCKED |
| Model produces no findings without quality-policy completion | INCONCLUSIVE |
| Any confirmed blocking finding | FAIL, no merge |
| No authentic post-publication GitHub review-ID witness | BLOCKED |
| Actual verified automatic run, but policy migration not merged | BLOCKED |
| Missing HUMAN_GO or sensitive-change approval | BLOCKED |

## Work prepared today

- Public Publisher candidate source:
  `candidate/keyless-review-binding.mjs`. It validates exact private
  target metadata and report/run/engine/builder digests, refuses
  type-coercion and noncanonical bytes, and explicitly returns
  `approvalAuthorized:false` and `reviewIndependenceVerified:false`.
- Offline synthetic regression tests:
  `test/keyless-review-binding.test.mjs` exercise stale identities,
  forgery, ambiguous types and the lack of approval.
- Manual proof workflow:
  `.github/workflows/reviewer-b-keyless-synthetic-proof.yml`.
  That separate public synthetic proof is not deployed to protected
  `main` or a live private-code analysis workflow.
- Actual future workflow name
  `.github/workflows/reviewer-b-live-review.yml` is **reserved by this
  proposed binding**; it does NOT exist and MUST NOT be treated as deployed.

## What still requires GitHub UI / operator, regardless of chat permission

- Independently satisfy existing protected branch/review rules or formally
  change them using the authorized governance process. Do not bypass a
  protection by force-pushing, turning off checks or impersonating a reviewer.
- Merge and test the NO-SECRET Publisher #3 environment probe; verify
  the hold-and-release ceremony (two existing accounts, not third).
- Approve GitHub App `Contents: Read` and `Issues: Read` for one
  PRIVATE repo, and no write to contents/issues/admin.
- After privileged workflow code has been reviewed and authorized, create
  and provision real keys directly into the protected environment, NOT
  ChatGPT, MSI, public CI or PR comments.
- Consent separately to private-source exposure and any Gemini provider
  billing. Prefer no paid API unless explicitly approved.

## Reference

GitHub CLI `gh attestation verify`: 
https://cli.github.com/manual/gh_attestation_verify

GitHub Actions `actions/attest`:
https://github.com/actions/attest

The user granted broad implementation consent; that does not constitute a
specific GitHub review on a changing commit SHA, a cryptographic signature,
an installed App scope, an environment approval or a new canonical HUMAN_GO.
