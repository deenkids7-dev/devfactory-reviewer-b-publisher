# Reviewer B: compatibility with canonical DevFactory native-review adapter

Status: design contract, **not production authorization**. Reviewed against
the open draft DevFactory PR #900, not merged code. Changes to PR #900 require
a fresh compatibility audit. This repository remains PUBLIC; no private
DevFactory diff, source, report, identity secret, or live token is allowed here.

## Two distinct cryptographic layers, not two reviewers

1. **Independent analyzer** (MISSING): produces an actual review and an
   Ed25519-signed attestation describing a specific repository, PR number,
   HEAD SHA, BASE SHA, diff SHA-256 and raw report SHA-256. The public
   verifier validates only the signature/integrity, not analyzer independence.
2. **Isolated Publisher** (MISSING): obtains its own authenticated and fresh
   GitHub PR/HEAD/BASE evidence, checks the full report and the independent
   analyzer's genuine provenance against a *separate* trust authority,
   verifies canonical HUMAN_GO clearance and the applicable policy, then
   prepares a native GitHub App review. No app token, private key or secret
   exists in this prototype.
3. **Existing DevFactory PR #900 adapter**, a *consumer* of native review
   evidence, not the producer: verifies a distinct RSA-SHA256 signature and
   an external trusted execution witness bound to the actual GitHub review.

A valid Ed25519 signature MUST NOT be passed as the RSA signature expected
by PR #900. RSA signing identity for the review marker must be separately
pinned and must never be confused with the GitHub App's JWT key.

## Native GitHub review wire contract expected by PR #900

Review user: `devfactory-reviewer-b[bot]` (GitHub user ID 340237276).
App installation: 169674558. App ID supplied by owner UI: 5253138.
Target repository: `deenkids7-dev/deenkids`.

The review text begins exactly with an HTML marker with protocol prefix
`devfactory-reviewer-b-native:v1:`, a BASE64URL-encoded UTF-8 JSON envelope,
then a newline followed by the exact report text. The envelope has exactly
`payload` and `signature`; the latter is an RSA-SHA256 base64url
signature of the adapter's lexicographically sorted JSON payload.

The signed payload has exactly these twelve fields:

- `repository`: exact target name.
- `pr_number`: positive integer; exact live PR.
- `head_sha`, `base_sha`: exact lowercase 40-hex commit hashes.
- `app_bot_id`: 340237276.
- `installation_id`: 169674558.
- `verdict`: `PASS` or `FAIL` only.
- `report_sha256`: SHA-256 of the *exact native review report text*.
- `nonce`: 32-128 lowercase hexadecimal chars, never reused.
- `reviewer_run_id`: 8-180 chars; trusted, unique independent run identity.
- `provenance_ref`: 8-240 chars; resolvable independent provenance reference.
- `completed_at`: analysis-completion instant, prior to publication.

Future implementers MUST derive this schema from the canonical PR #900 adapter
at its reviewed HEAD; never trust this prose as a replacement for automated
cross-repository checks.
The adapter binds RSA signature to a GitHub review made by the exact bot,
on the exact commit, with GitHub review state APPROVED for PASS or
CHANGES_REQUESTED for FAIL, and verifies report digest/independent execution.

## Mandatory authorization gates

- [ ] Independent analyzer actually runs, with meaningful review findings.
- [ ] Independently provisioned and pinned analyzer trust root. The tests'
      ephemeral keys MUST NEVER be trusted in production.
- [ ] Real, authenticated provenance witness, stored outside the code
      author's write boundary, binding exact report/run/scope/commit/review.
- [ ] Real live GitHub PR diff and exact HEAD/BASE verified by a trusted client.
- [ ] Canonical GitHub HUMAN_GO clearance from existing DevFactory authority.
      Never create a parallel operator-approval ledger or clearance pathway.
- [ ] Publisher receives secrets only inside a protected job on trusted main,
      with an independent security review of every workflow change.
- [ ] Single-use nonce verified atomically against authoritative record.
      Github's already-existing review identity may provide the record;
      never invent a second DevFactory State Ledger.
- [ ] Re-fetch current GitHub HEAD before any write; if changed => STOP.
- [ ] After native review publication, validate the GitHub-assigned review ID,
      actual author ID, state, report body, commit and provenance binding.
      Never claim PR #900 PASS before its independent verifier accepts this.
- [ ] No merges of private DevFactory PRs #898-#901 without separate
      independent review and explicit canonical clearance.

## Critical binding limitations

The GitHub review ID is assigned only **after** submission. Therefore, an
external provenance resolver must bind the signed analysis and native GitHub
review to that assigned ID using trusted evidence, without treating any
claim in review body as proof. A local callback that always returns true
is forbidden.

The protected Publisher environment currently has only one possible
approving user, the same account that can author its workflows. Its manual
approval is an operator control, not independent security approval.
Do not introduce production secrets there until this trust boundary is
reviewed and strengthened.

The current PR includes only a cryptographic *fixture verifier*.
It does not install or use the GitHub App, and it never approves PRs.
