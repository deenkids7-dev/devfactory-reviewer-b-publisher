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
