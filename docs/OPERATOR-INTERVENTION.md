# Operator intervention gates — Reviewer B independent Publisher

This public repository contains **no active Publisher** and no private repo
data. Do not treat a green CI as proof of independent review. Current
prototype uses synthetic keys and fake diff fixtures only.

## Completed technical foundations

- Hosted GitHub runner, separate account and protected Publisher `main`.
- Secret-free CI executes code at immutable PR HEAD (rejects fork HEADs).
- Exact identity fields: `deenkids7-dev/deenkids`, repository ID 1282086207,
  SHA-1 HEAD/BASE and diff/report SHA-256; no GitHub live-read client yet.
- Canonical Ed25519 claim verification, anti-malleability and test replay check.
- Bounded canonical findings/report correlation; no LLM PASS => approval.
- RSA native review **wire format only** compatible with draft DevFactory
  PR #900 (no GitHub API write, no signing key, no review event).
- CI prohibits production secrets and GitHub write endpoints in prototype code.

## First operator action required: independent environment reviewer

On `devfactory-reviewer-service/devfactory-reviewer-b-publisher`:

1. Settings > Environments > `reviewer-b-publish`.
2. Check Required reviewers; **replace** `devfactory-reviewer-service`
   with `deenkids7-dev`, **if GitHub permits choosing a public-repo reader
   without granting collaborator/write privileges**.
3. Enable `Prevent self-review`. Leave administrator bypass disabled.
4. Keep Deployment branches as `Protected branches only`.
5. Save protection rules. Capture the result (no secrets).

If GitHub will not allow a distinct reviewer without adding collaborator
write rights to the Publisher repository, STOP. Do not add `deenkids7-dev`
as a write collaborator, because the original MSI OAuth could then modify
the independent publisher code. Choose another independently controlled
account with only necessary deployment-review rights or redesign the gate.

This review is an OPERATOR deployment authorization only. It never
constitutes an independent code review or signed analysis provenance.

## Later human actions — only after a trusted publisher is reviewed

- Review final Publisher source/workflow on exact HEAD and enforce stronger
  code-owner/branch checks that a code author cannot self-approve.
- On a separate trusted device, generate a GitHub App private key using
  DevFactory Reviewer B (owner `deenkids7-dev`, App ID 5253138).
- Provision ONLY the required environment secret inside the independent
  `reviewer-b-publish` environment. Never place private keys in ChatGPT,
  a ticket, the public repository, public Actions logs, PR fixtures, or MSI.
- Provision a **separate** RSA signature key if PR #900's native evidence
  adapter remains unchanged. DO NOT reuse GitHub App JWT private key for
  evidence signatures. Pin the RSA SPKI public-key SHA-256 in trusted DevFactory
  configuration after reviewing canonical protocol.
- Choose/provision an actual independent reviewer engine/provider with
  explicit budget/zero-surprise spend and credentials isolated from code
  authors, not the MSI runner or DevFactory's own agent credential set.
- Validate trusted GitHub API read of private HEAD/BASE/diff without logging
  private source to public CI. Implement reviewed transport and provenance
  witnesses before enabling any real publish job.
- Confirm canonical HUMAN_GO clearance separately, with exact PR/commit and
  existing authority. No new controller or competing approval ledger.

## Publication and merge remain STOP

- No App JWT or short-lived installation token exists in this repo.
- No analysis engine or independently validated provenance exists.
- No durable atomic anti-replay or idempotent GitHub-native review publisher.
- No production event APPROVE or REQUEST_CHANGES may be selected by prototype.
- Do not approve or merge private PRs #898/#899/#900/#901 on this basis.
- Do not merge Publisher PR #2 without a separate technical security review.

## Free-tier note

The public Publisher repository can use GitHub-hosted Actions on the free
tier, but external AI inference may incur usage fees. Do not sign up for or
activate provider billing without explicit operator budget approval.
