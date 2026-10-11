# GitHub App native COMMENT-only canary — release contract

**Not a review APPROVAL. Not an independent human reviewer. Not a
Sigstore-attested PRIVATE report.** This is a proof of native GitHub App
COMMENTED publication only, after PRIVATE read verified in run 38140023698.

## Prerequisites

1. PUBLIC Publisher main stays branch protected, with latest trusted code
   reviewed and exact-head CI PASS. Existing App ID 5253138, installation
   169674558, repository ID 1282086207 and bot user 340237276 must match.
2. A protected `reviewer-b-publish` environment approved by the existing
   `deenkids7-dev` approver provides PEM via environment secret
   `REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM`, never copied to local files/logs.
3. The workflow is triggered **once only**, by service-actor merge of the
   marker path on protected PUBLIC main; PR #899 is hard coded. No
   user-controlled PR target or code from PRIVATE PR is executable.
4. Workflow-level `permissions: {}`, protected source at SHA, exact
   actor/ref/event, fixed `concurrency` group, 5-minute timeout.
5. Two GitHub App installation tokens with disjoint permissions:
   `reviewRead` = Contents:read + Pull requests:read;
   `publish` = Pull requests:write ONLY, no Contents access.
6. Immutable PR diff is read with bounded response and static audit;
   static FAIL or contradictory/malformed result BLOCKS publication.
   Only a safe INCONCLUSIVE preflight permits a COMMENTED proof.
7. Native reviewer identity is checked against GitHub App bot ID 340237276,
   login `devfactory-reviewer-b[bot]`. The exact PR HEAD must be stable
   both before and after the write. Existing bot reviews on current HEAD
   block repeat writes; a fixed concurrency group covers workflow races.
8. Native review POST forces `event:'COMMENT'` (never APPROVE), and
   readback must prove exactly one bot COMMENTED on current HEAD. Public
   logs report only the constant `PROTECTED_NATIVE_COMMENT_...` outcome,
   never token, PEM, filename, source, private report or review body.
9. This proof produces `approvalAuthorized:false`,
   `independentReviewVerified:false`, `reviewerPass:false`,
   `attestedReportVerified:false`, `humanGoVerified:false`.

If successful, the private PR will show a genuine GitHub App COMMENTED
review with report/diff digests but no source code or claimed security PASS.
It does **not** satisfy DevFactory's independent review gate. The real
quality-scored semantic engine, private report certificate verifier and
policy branch `AUTOMATED_ATTESTED` remain release-blocked separately.
No reviewer can authorize master merges from this canary.
