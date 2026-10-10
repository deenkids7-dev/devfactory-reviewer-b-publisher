# Publisher organization transfer verification (2026-10-10)

**State:** transferred, verified, still a prototype. This record is not
independent code review, signing authority, or production authorization.

## Repository and access

- Canonical current repository:
  `devfactory-reviewer-trust/devfactory-reviewer-b-publisher` (PUBLIC).
- Historical owner:
  `devfactory-reviewer-service/devfactory-reviewer-b-publisher`.
- GitHub repository ID remained `1412898356`.
- Organization: `devfactory-reviewer-trust`.
- Service account `devfactory-reviewer-service`: admin/push confirmed by
  GitHub connector; source of authorized development changes.
- Main DevFactory account `deenkids7-dev`: pull=true, push=false,
  admin=false confirmed on the transferred repository.
- Org base repository permissions: Read, confirmed by owner UI.
- Org membership: `devfactory-reviewer-service` Owner and
  `deenkids7-dev` Member, confirmed by owner UI.

## Environment gate

Owner reported saving the following `reviewer-b-publish` configuration:
- Required reviewers: only `deenkids7-dev`.
- Prevent self-review: ON.
- Administrator bypass: OFF.
- Deployment branches: protected branches only.

This configuration was evidenced via owner screenshot before saving and
followed by owner's confirmation of Save. It has NOT yet been independently
read via GitHub's authenticated Environments API or demonstrated by a
secret-free hold/release test. **Treat live operation as UNVERIFIED** until
that exercise is completed.

This environment approval is an operator separation control. Since the
person controls both GitHub accounts, it is NOT an independent security
review of code, nor genuine provenance of an independent analyzer.

## Repository and CI after transfer

- PR #2 preserved, open and DRAFT, not merged.
- Protected `main` preserved (GitHub branch summary API).
- Both PR check names preserved:
  `Verify independent runner` and
  `Verify fail-closed attestation logic`.
- GitHub app `ChatGPT Codex Connector` was authorized for the transferred
  organization, scoped to the Publisher repository; actual successful
  repository write through secondary connector confirmed.
- Both workflow repository-identity checks changed from the old account
  to the new organization. GitHub Actions PASS on the exact commit
  `9696bc8b01ab4cd480dd9d265966ed25986463e0`.

Do not assume more than the facts above. In particular, CI success on
synthetic fixtures is not evidence of an actual independent reviewer.

## Outstanding security and functional gates

1. Genuine independent analyzer, reviewer model and separate trust domain.
2. Authenticated, private GitHub API target read, bounded exact PR scope.
3. Genuine provenance witness, signing-key pinning and key custody.
4. Durable atomic anti-replay, canonical HUMAN_GO, idempotent review publish.
5. A reviewed production publish workflow with no code-author path to
   self-authorization or private-source leakage.
6. Exact review-ID and author/provenance validation against DevFactory
   native review consumer in PR #900.
7. Independent review of the Publisher code and policy before deployment.
8. Deployment-environment no-secrets hold/release proof.

**STOP:** never interpret the current draft as ready to APPROVE,
REQUEST_CHANGES, merge the Publisher PR, or unblock private DevFactory PRs
#898/#899/#900/#901.
