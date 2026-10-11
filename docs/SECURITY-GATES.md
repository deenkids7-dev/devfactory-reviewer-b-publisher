# Reviewer B — Fail-closed security gates

Status: prototype verification only, NOT a live Publisher.

## Existing evidence (limited)

- Publisher repository is separate from the private deenkids repo.
- A GitHub-hosted smoke workflow passed in the Publisher repository.
- Main requires the Verify independent runner status check (operator-configured).
- Existing DevFactory Reviewer B GitHub App is owned by deenkids7-dev.
- App ID from owner UI: 5253138. It has Metadata read + Pull requests read/write,
  installed on the single private deenkids7-dev/deenkids repository.
- GitHub App owner UI showed zero private key pairs at bootstrap.

## Every item below is UNMET in prototype; missing item => STOP

- [ ] Genuine reviewer engine separate from DevFactory runtime, Publisher, and MSI.
- [ ] Authentic independent signing identity and pinned public key from trusted channel.
- [ ] Verified provenance tying independent review to exact requested scope and HEAD.
- [ ] Trusted GitHub API fetch of repository ID, PR number, open state, HEAD, BASE and raw diff hash.
- [ ] Authenticated operator HUMAN_GO under canonical GitHub policy, separate from report.
- [ ] Durable anti-replay and serialized processing (no new duplicate ledger/controller).
- [ ] Atomic nonce consumption and idempotent review publishing.
- [ ] Recheck HEAD immediately before publication, refusing movement.
- [ ] Protected secret-bearing publication job on trusted main with no untrusted code.
- [ ] Private-source protection: never log private diffs or reports to public Actions.
- [ ] Real negative/live dry-run tests, including rejection of stale or forged evidence.
- [ ] Independent quality review of this Publisher PR, plus operator authorization.
- [ ] Approval policy (do not infer from cryptographic verification).

The verifier returns approvalAuthorized=false and reviewIndependenceVerified=false
for EVERY accepted signed fixture, including disposition PASS.

## Non-duplication

No new scheduler, supervisor, retry manager, model router, State Ledger, audit engine,
merge executor or competing GitHub HUMAN_GO authority. Do not alter or merge
deenkids PRs #898, #899, #900, #901 while the above gates are missing.
