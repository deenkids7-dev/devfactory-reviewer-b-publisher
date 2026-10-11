# Reviewer B — remaining human-only release gates

**Prepared 2026-10-11; NOT an authorization, deployment or review PASS.**
This is a runbook for the existing two GitHub accounts only:
`devfactory-reviewer-service` (Publisher owner) and `deenkids7-dev`
(DevFactory author and existing Publisher environment approver).

These accounts are co-owned. GitHub account separation and Sigstore
provenance prove *technical* boundaries, not independent human judgment.
Do not mislabel this as an independent security sign-off.

## Frozen baseline to check again before acting

- Publisher: `devfactory-reviewer-trust/devfactory-reviewer-b-publisher`
  on public `main`; branch `feat/reviewer-b-attestation-verifier-v1`,
  PR #2. PR #3 is the bootstrap of the environment/required checks.
- Private source: `deenkids7-dev/deenkids` on `master`.
  Open PRs #898, #899, #900 (draft), #901 (draft), #878.
  Issues #895 and #876 must not be mistaken for PRs.
- Publisher #2 code is **prototype**: private source read and native review
  publication are dormant. Green CI alone does not unlock the branch.
- No billed model, App private key, native RSA key, external Ed25519
  witness key or real private PR review has been provisioned by this runbook.

## Stage A — explicit policy / security release decision (manual)

**Owner must make an explicit, recorded choice before merging protected
security-critical code**:

A. Keep the current contract and commission an **independently accountable
security review** of the final exact HEAD of the Publisher and the private
native adapter before any production keys or protected merge; or

B. Formally propose and review a change to the DevFactory approval contract:
`AUTOMATED_ATTESTED` as a **distinct** origin-verifiable automated review
class, **not** a reinterpretation of `INDEPENDENT_HUMAN`. Keep all existing
exact-HEAD, CI, HUMAN_GO, high-risk human approval, permission separation,
contradictory-finding and revocation rules. The private native adapter and
Merge Executor must gain a separately reviewed, tested admission path before
this alternative can go live. Current PR #900 does **not** implement it.

No model comments, owner review from a second co-owned account, second
self-held key, GitHub artifact attestation or unit-test PASS alone can
satisfy the existing external-human security gate. Until the selected
contract is legitimately updated and accepted, protected merges remain STOP.

## Stage B — Publisher public bootstrap (manual after Stage A)

1. Open Publisher PR #3:
   https://github.com/devfactory-reviewer-trust/devfactory-reviewer-b-publisher/pull/3
   Review current exact HEAD and both required CI checks. Obtain the review
   and the separate exact-head permission required by the *effective*
   protected branch policy. Do NOT switch off required checks or bypass
   branch protection. Merge through GitHub only when actually authorized.
2. In GitHub Settings of the PUBLIC Publisher, inspect the protected
   `main` branch and environment `reviewer-b-publish`: required CI
   `Verify independent runner`, `Verify fail-closed attestation logic`,
   prevent self-review ON, administrator bypass OFF, only protected branches.
3. Manually dispatch `Reviewer B - No-secret environment approval probe`
   from `main` using `devfactory-reviewer-service`. It must enter WAITING.
   Approve that *specific* pending environment job from the configured
   approver account `deenkids7-dev`. Verify final
   `NO_SECRETS_APPROVAL_GATE_RELEASED` evidence, approver actor and run ID.
   This does NOT prove independent human code review.
4. Reconcile Publisher PR #2 against the updated `main`, and re-run ALL
   its exact-head checks. Review new changes and authorize its merge only
   through the current or formally revised security/merge policy.
5. When its keyless synthetic workflow is merged and approved on protected
   `main`, manually dispatch `Reviewer B - Keyless synthetic provenance
   proof` with `devfactory-reviewer-service`; have the existing
   `reviewer-b-publish` environment approver release this specific run.
   Verify the resulting attestation via the documented exact signer workflow
   and protected ref. If Actions restrictions block the pinned GitHub-owned
   `actions/attest` action, narrowly allow ONLY that reviewed action;
   do not turn on all marketplace actions. Record actual run ID/attestation.
   A synthetic attestation is **not** a Reviewer B PASS.

## Stage C — PRIVATE code permission and secure execution (manual)

6. On GitHub, open **Developer settings > GitHub Apps > DevFactory Reviewer B
   > Permissions & events** as its actual owner. After independently auditing
   the scope, approve `Contents: Read` and `Issues: Read`; retain
   `Pull requests: Read and write` and `Metadata: Read`.
   Keep installation limited to PRIVATE `deenkids7-dev/deenkids` only.
   Do not grant `Contents: Write`, `Issues: Write` or administration.
   Confirm any GitHub-requested installation permission update. App ID from
   historical operator state is 5253138; re-check in GitHub UI.
7. Only after a verified reviewed *privileged* workflow is deployed, create
   a fresh GitHub App JWT key in GitHub's secure UI and provision it directly
   into the protected GitHub Actions environment. Keep distinct purpose-bound
   installation tokens for read, Issue authority and write. Never paste
   private keys, tokens, private diffs or private reports into ChatGPT, the
   public repo, a PR comment, or MSI logs.
8. If retaining current private PR #900 contract, separately provision its
   native RSA signing key AND independently controlled external Ed25519
   witness after a trusted reviewer has audited the signer, runtime,
   provenance and key isolation. A second key held by the same operator is
   NOT independent provenance. If Stage A instead approved option B, implement,
   audit, test and merge its alternate adapter **before** any production
   credentials or live acceptance.
9. Decide the semantic engine and data exposure/budget policy. Gemini Code
   Assist private-repo setup may require Google Cloud billing even during a
   free Preview. No billing may be enabled by a silent default. Offline Qwen
   on a future separately controlled host is an alternative, not deployed.

## Stage D — real acceptance and private merges (manual HUMAN_GO)

10. On a deliberate PRIVATE test PR, collect authentic immutable GitHub
    read, bounded report with real findings, signed execution provenance
    or approved independent witness, native GitHub App review ID, re-read
    exact HEAD/BASE and replay guards; verify both positives and forged,
    stale, moved-head and contradictory negatives end-to-end.
11. Apply existing GitHub canonical HUMAN_GO to each specific PR/HEAD.
    Never turn Gemini COMMENTED into native APPROVED or copy a fake PASS.
    Then process #899 (CI adapter), #898 (reclearance), #900 (native evidence),
    #901 (launcher) in the actual dependency order established by fresh
    code/CI/review checks. Recover #895 and #876/#878 only with their
    historical authority/lineage constraints and fresh reviews.
    Resume Plan Maître only after a real restart/health audit.

## Automatic stopping conditions

Any missing stage A decision, unsigned/unauthenticated proof, HEAD drift,
missing GitHub App scope, environment release not recorded, unapproved
external private-source transfer, secrets in logs, missing exact-head CI or
independent/approved attested review evidence => STOP. Never substitute
a synthetic test or a co-owned account approval for missing authority.

Links:
- Publisher PR #2: https://github.com/devfactory-reviewer-trust/devfactory-reviewer-b-publisher/pull/2
- Publisher PR #3: https://github.com/devfactory-reviewer-trust/devfactory-reviewer-b-publisher/pull/3
- Private Reviewer B PR #900: https://github.com/deenkids7-dev/deenkids/pull/900
- Exact proof procedure: docs/KEYLESS-PROVENANCE-SYNTHETIC.md
