# Deployment approver separation — zero-secret migration runbook

**Status:** PREPARATION ONLY. No repository transfer, identity change, GitHub
App key provisioning, required-reviewer change, or protected-branch merge
is authorized by this document.

## Why the current account cannot safely grant reviewer access

The Publisher belongs to a **personal GitHub account**,
`devfactory-reviewer-service`. GitHub personal repositories do not support
a separate repository collaborator with a granular read-only role.
The account `deenkids7-dev` is not an eligible selectable environment
reviewer in the current UI. Adding it as a collaborator would grant write
capability and could give the MSI's existing credential a path to change
Publisher code. DO NOT DO THIS.

GitHub organization-owned repositories support granular Read/Write roles.
Free organizations can host PUBLIC repositories with branch protection and
environment required reviewers. Keep this repository public but **never**
put private `deenkids` source, reports, signing keys or token values in it.

## Proposed organization trust layout

- Organization owner: `devfactory-reviewer-service`, the separate service
  account (the current publisher maintainer). This is a practical incremental
  split, NOT complete resistance against an intentionally malicious org owner.
- Additional organization member: `deenkids7-dev`, **member not owner**.
- Organization base repository access: **Read**, NOT Write.
- Explicit Publisher access for `deenkids7-dev`: Read (or no extra grant
  beyond inherited Read). Do NOT grant Write, Maintain, Admin or org Owner.
- Publisher code changes: separate service account's feature branches via PR,
  protected `main`, full-SHA workflow pin rules and required CI.
- Environment `reviewer-b-publish`: approver `deenkids7-dev`, not the
  initiating service account. `Prevent self-review` ON, bypass OFF,
  deployment branches `Protected branches only`.
- Do not grant the MSI any new GitHub permissions.

**Residual risk:** Org owners still administer repository settings. This
split prevents ordinary automated self-approval, but a compromised owner
could deliberately change settings. Before production key provisioning,
use an additional independent administrative trust domain and monitor
environment/branch-protection changes. GitHub's environment approval alone
is NOT proof of independent analysis.

## Operator-controlled sequence (nothing executed yet)

1. While logged in as `devfactory-reviewer-service`, create a **GitHub Free
   organization**, avoiding a paid upgrade or billing authorization.
2. Keep this service account as organization owner for now.
3. Invite `deenkids7-dev` as an organization **member**, NEVER Owner; the
   account owner must accept the invitation. Confirm organization base
   permissions are `Read`.
4. Verify that `deenkids7-dev` has NO repository Write/Maintain/Admin
   permission. Do not give it an org role which inherits admin.
5. Capture original repository protections, Actions restrictions, workflow
   files, environment settings and SHA. Confirm a repository transfer can
   retain or restore each property. No secrets exist at present.
6. Only with a separately approved change window, transfer the
   **PUBLIC Publisher repository only** into that organization. DO NOT
   transfer the private `deenkids7-dev/deenkids` repository.
7. Reverify exact project identity/URL; old GitHub URLs may redirect, but
   every security rule and every connected GitHub account must be inspected
   and re-bound deliberately to the new organization repository.
8. Re-enable/recheck `main` protection with `Verify independent runner`
   and `Verify fail-closed attestation logic` required; no bypass, force
   push or direct protected-main writes. Validate SHA and PR #2 state.
9. In `reviewer-b-publish`, select the primary account as Required reviewer;
   remove service self-approval; enable Prevent self-review; bypass OFF;
   protected branches only. Save.
10. Verify using a NO-SECRETS deployment hold test initiated by the service
    account that only the separate approver can release; do NOT approve a
    real deployment or provision private keys just to test this step.
11. Confirm the new security controls are effective before planning a
    separate private-key ceremony and independently attested review engine.
12. If the required-reviewer picker still excludes the primary account,
    STOP and investigate role/organization eligibility. Do not grant Write
    just to populate the picker.

## Safety checks that must survive a repository transfer

- The original PR #2 must be preserved, unmixed and still unmerged.
- Both GitHub-hosted CI checks must pass on its new exact HEAD.
- Existing `main` protected branch and its review/CI settings must survive
  or be restored before touching production workflows.
- No workflow may load private repository contents in a public Actions log.
- No secret, private key, PAT, paid subscription or provider billing.
- Existing bot ID, App owner/install and DevFactory's private CI are unchanged.
- The two GitHub plugin connections should remain isolated by link/account.
- If any check cannot be established, publication remains BLOCKED.

## References (GitHub Docs, Oct 2026)

- Personal account permissions:
  https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/permission-levels-for-a-personal-account-repository
- Deployment required reviewers:
  https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
- Organization roles:
  https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization
- Repository transfer:
  https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository
