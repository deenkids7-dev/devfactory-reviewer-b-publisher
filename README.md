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
