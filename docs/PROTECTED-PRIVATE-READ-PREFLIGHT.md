# Protected private source READ-only preflight — prepared, NOT deployed

Status 2026-10-11: **candidate module + synthetic integration tests ONLY.**
There is no production privileged workflow, key, approved private-source
transfer or native Reviewer B approval.

`candidate/scoped-private-read-preflight.mjs` joins EXISTING modules:

1. The owner-provisioned GitHub App RSA JWT generator
   `candidate/github-app-auth.mjs`.
2. The purpose-bound installation token factory, restricted to exact
   repository ID 1282086207 and **Contents:read + Pull requests:read**
   (no Issues read, PR write, Contents write or other privilege).
3. `candidate/private-review-preflight.mjs` with authenticated PR metadata
   before/after, immutable BASE...HEAD compare diff and bounded fail-only
   static audit. It cannot send data to a model or publish GitHub reviews.

A result is always **INCONCLUSIVE** or contains fail-only *provisional*
findings. It always has `approvalAuthorized:false`, `publishEvent:null`
and `independentReviewVerified:false`. It is never a Reviewer B PASS.

The private GitHub App PEM is injected exclusively by a future trusted
protected environment, not read from local disk or a PR. Normal inspection,
serialization and JSON do not include the PEM, short-lived installation
token, raw diff, private report bytes or private file paths. The caller may
access a redacted protected report getter; do not log that getter.

Synthetic negative tests enforce token scope, no write endpoint, HEAD drift,
invalid PR selector, missing PEM and sanitization. Synthetic test keys and
source are NOT production access or a real independent reviewer.

## Remaining privileged integration

- Review the future `reviewer-b-live-review.yml` under protected public
  Publisher `main`, with manual dispatch, existing environment
  `reviewer-b-publish` and approved actor, before provisioning any key.
- Approve the exact GitHub App `Contents:Read` permission and installation
  on PRIVATE `deenkids7-dev/deenkids`.
- Provision a GitHub App PEM only inside the protected environment; verify
  real installation ID and test the immutable compare read without logging
  source. Never copy PEM into ChatGPT, MSI, PR comments or public logs.
- The real semantic reviewer, GitHub/Sigstore signer/source verification,
  report finding quality, post-review witness and canonical HUMAN_GO must
  be implemented and verified before the first native approval.
- A signed PUBLIC *synthetic* attestation alone never proves a private
  review. Do not merge PR #2 or private #900 based on these tests alone.

No new controller, scheduler, paid API, reviewer account, CodeRabbit
integration, additional review authority or merge executor is added.
