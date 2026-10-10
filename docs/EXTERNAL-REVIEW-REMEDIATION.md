# CodeRabbit external review reconciliation — 2026-10-10

This is the Publisher author's **own remediation log**, NOT an independent
review, approval, or evidence that the latest HEAD was reviewed externally.

## Independent third-party input (stale for current HEAD)

- PR: https://github.com/devfactory-reviewer-trust/devfactory-reviewer-b-publisher/pull/2
- CodeRabbit COMMENTED review ID: 5478886673
- Reviewed head (historical): 906c79cf387b517af26710a9edffbca7607fe122
- External review produced 13 inline actionable remarks. It did NOT APPROVE
  the PR or authenticate a Reviewer B review of private DevFactory.
- The Publisher branch has since changed. Every security finding must be
  independently verified again at the FINAL exact head.

## Remediation checklist (author-assessed, not external PASS)

- [x] Risky pull_request_target YAML forms trigger a fail-only finding
      (candidate/fail-only-static-audit.mjs).
- [x] GitHub native review list re-fetches the real PR HEAD before and after
      pagination and binds observed target SHA
      (candidate/github-review-readback.mjs).
- [x] RSA native marker signer forbids signed PASS in candidate stage
      (candidate/native-marker-sign.mjs).
- [x] Documentation spelling and owner/approver trust separation corrected
      (docs/INDEPENDENT-SECURITY-REVIEW-PACKET.md,
      docs/NATIVE-REVIEW-COMPATIBILITY.md,
      docs/PREKEY-READINESS.md).
- [x] Historical organization transfer runbook explicitly superseded,
      with live-state pointers (docs/ORG-APPROVER-MIGRATION.md).
- [x] Minimum Node version raised to 20.11.0 (package.json).
- [x] Native review signature bytes sort signed fields deterministically,
      independent of host locale (src/native-review-wire.mjs).
- [x] Signed native completed_at demands strict canonical UTC timestamp
      (src/native-review-wire.mjs).
- [x] GitHub PR diff fetched with immutable compare BASE...HEAD,
      then metadata re-read and exact changed-file coverage enforced
      (src/github-pr-observer.mjs, src/pr-snapshot-consistency.mjs).
      Synthetic tests do not prove transport or independent source.
- [x] Negative GitHub API tests check specific error modes
      (test/github-read-only.test.mjs).
- [x] Tests ban any GitHub write permission, including job-level overrides,
      and keep environment probe manual/no-secret
      (test/prototype-boundary.test.mjs,
      test/environment-probe-contract.test.mjs).
- [x] Broken-JSON and one-byte-sized envelope cases tested separately
      (test/strict-envelope.test.mjs).

## Additional safeguards after external review

- [x] DeepSeek Flash/Pro model request candidate: no real HTTP, credentials,
      source disclosure or paid calls.
- [x] Reject model-authored PASS and model-authored finding fingerprints;
      derive fingerprints deterministically from bounded normalized data.
- [x] Filter truncated/wrong-model responses and usage above explicit
      expected ceilings; pricing remains indicative, not actual billing.
- [x] Carry private canonical findings to a separate eventual signer without
      including the content in ordinary JSON, object spread or inspection.
- [x] Offline end-to-end testing of fake DeepSeek reply, static findings,
      combined report and ephemeral signed attestation.
- [x] Seeded workflow static benchmark, including new GitHub token-write
      scope detection; fail-only warnings are not independent approval.

## Critical blockers — MUST NOT be marked as fixed

- [ ] Independent security review on CURRENT FINAL HEAD, not old review.
- [ ] Security review of the production protected Publisher workflow.
- [ ] Proof of independent execution/model provenance and signer trust root.
- [ ] Operator-authorized private source disclosure and spending ceiling.
- [ ] Demonstrated no-secret protected environment hold/release on main.
- [ ] GitHub App key, downscoped installation token and Issues:Read permission
      controlled under the original DevFactory canonical HUMAN_GO authority.
- [ ] Persistent replay/idempotence and race-safe native GitHub review writer.
- [ ] Validation against private draft DevFactory PR #900 at its exact HEAD.
- [ ] No private DevFactory PR #898–#901 review approved or merged.

**Do not merge Publisher PR #2 as production ready.** Never infer a real
independent Reviewer B PASS from CodeRabbit's review of this PUBLIC repo,
synthetic CI, or private source passed into an external model.
