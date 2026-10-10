# DevFactory Reviewer B — Independent Publisher foundation

**PROTOTYPE ONLY — NO REAL REVIEWER, NO PUBLISHER, NO APPROVAL.**

This separate public repository will eventually host the verifiable publication
boundary for independent DevFactory reviews. Its current implementation only
tests an Ed25519-signed attestation from an EPHEMERAL test signer; it has no
GitHub review endpoint, secret-bearing job, installation token, or approval path.

## What is implemented

- Strict schema for claimed target repository/PR, HEAD, BASE and diff SHA-256.
- Strict schema for report digest, signer identifier, review identifier and nonce.
- Deterministic JSON serialization used by both signer test fixture and verifier.
- Ed25519 cryptographic verification against a separately supplied trusted key map.
- Expiration and replay-identifier checks against caller-supplied snapshots.
- Rejection of wrong repository/PR/commit, invalid digest, tampering and bad keys.
- Result always has approvalAuthorized=false and reviewIndependenceVerified=false.
- Secret-free GitHub Actions CI on PRs, with read-only token and no third-party actions.

Important: a Set of seen nonces supplied in a test does not constitute persistent
anti-replay protection. A trustedTarget supplied by a test is not a live GitHub
attestation. A claimed PASS is not independently verified quality or permission
to approve. This repository has not yet implemented these missing controls.

## Additional fail-closed prototype components

- `src/strict-envelope.mjs`: parses only canonical UTF-8 signed bytes,
  rejecting ambiguous JSON, duplicate keys and oversized reports.
- `src/pr-snapshot-consistency.mjs`: checks consistency of **supplied**
  PR metadata before/after supplied text-only diff bytes. It has NO
  authenticated GitHub transport, so it cannot establish live provenance.
- `src/native-review-wire.mjs`: verifies a *detached* RSA-SHA256 signature
  and formats a synthetic native-review marker compatible with the existing
  adapter planned in DevFactory PR #900. It DOES NOT sign, publish, select
  APPROVE/REQUEST_CHANGES or authorize an action. `publishEvent` is always
  `null`.
- `docs/NATIVE-REVIEW-COMPATIBILITY.md`: documents the two distinct signing
  layers (independent analyzer vs native Publisher), their exact trust
  boundaries and the unmapped provenance requirements.

All positive RSA/Ed25519 tests use **ephemeral synthetic keys**. These keys,
mock PR data and fixture PASS claims are not production evidence.

## Reproduce locally

Node.js 20+ with no external packages or secrets:

    npm test

The test signer keys exist only in RAM during test execution.
Do not deploy test keys or trust report-supplied public keys.

## Future publication requirements

See docs/SECURITY-GATES.md. No live publication can be enabled until the
independent analyzer, trusted signing identity, operator authorization, replay
authority, authenticated target read, private data isolation, and target-HEAD
revalidation have been implemented and externally reviewed.

Existing GitHub App: DevFactory Reviewer B, owned by deenkids7-dev, installed
on private deenkids7-dev/deenkids. Never move the App private key to MSI,
public Actions, untrusted pull request jobs, or conversation messages.

## Scope

This PR changes only the independent Publisher repository. It does not touch
the private deenkids repository or any of its blocked PRs.


## Current development branch — NOT a live reviewer (October 2026)

Additional `candidate/` modules on draft PR #2 cover simulated
read-only private-PR API transport, constrained App JWT issuance, limited
installation-token scope, signed model findings, native RSA marker signing,
offline fail-only scanning, bounded native review readback, and a
nonpublishing preflight. All privileged and independent-execution code is
**dormant**, uses only synthetic tests and provides no approval path.

The candidate static audit does not echo raw added source text; private
review plans redact JSON serialization and Node debug inspection. None of
these safeguards permits sending private source to a model without explicit
authorization and a separate, evaluated trust domain.

A manual-only, no-secret environment probe is staged in
`.github/workflows/reviewer-b-environment-hold-probe.yml`. It will
**not** run from the branch or certify environment protection until
a separately authorized, independently security-reviewed merge places
it on protected `main` and an operator explicitly releases the held
deployment. All PR CI remains secret-free.

## Low-cost in-house semantic Reviewer B (candidate, no API usage)

- `candidate/deepseek-review-contract.mjs`: deterministic review-request
  format for the current `deepseek-flash` API model (optional manual
  `deepseek-v4-pro` choice), no networking, keys, billing or private source
  disclosure. No automatic model routing or retry manager.
- Model findings are normalized by trusted code; model-authored fingerprints,
  PASS decisions and approval claims are rejected.
- Real model-usage ceilings and input-token context are mandatory before a
  response can be accepted, but pricing/token accounting are not yet
  independently proven. The code cannot authorize spending.
- `test/end-to-end-offline-review.test.mjs`: exercises fake Git diffs,
  fail-only static analysis, synthetic model findings, combination, Ed25519
  signing and verification. A clean result is INCONCLUSIVE, never PASS.
- `docs/DEEPSEEK-LOW-COST-OPERATIONS.md`: current pricing, privacy and
  independent-runtime operator plan.

**NO REAL MODEL CALL, EXTERNAL PRIVATE-CODE TRANSFER OR PAID RESOURCE IS
ENABLED.** API credentials and actual independent execution remain blocked
until distinct security reviews, operator consent and provenance proof.

See `docs/PREKEY-READINESS.md` for the required manual gate, separate
private-key roles, and outstanding provenance, model and publication work.
Do not create or provision real keys until those gates are closed.
