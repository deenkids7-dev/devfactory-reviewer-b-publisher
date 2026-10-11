# Operator intervention gates — Reviewer B independent Publisher

This public repository contains **no active Publisher** and no private repo
data. Do not treat a green CI as proof of independent review. Current
prototype uses synthetic keys and fake diff fixtures only.

## Completed technical foundations

- Hosted GitHub runner, separate account and protected Publisher `main`.
- Secret-free CI executes code at immutable PR HEAD (rejects fork HEADs).
- Exact identity fields: `deenkids7-dev/deenkids`, repository ID 1282086207,
  SHA-1 HEAD/BASE and diff/report SHA-256; a dormant authenticated read-only
  GitHub transport is implemented and synthetically tested, but has NOT read
  the private repo under a newly approved App Contents:Read token.
- Canonical Ed25519 claim verification, anti-malleability and test replay check.
- Bounded canonical findings/report correlation; no LLM PASS => approval.
- RSA native review **wire format only** compatible with draft DevFactory
  PR #900 (no GitHub API write, no signing key, no review event).
- CI prohibits production secrets and GitHub write endpoints in prototype code.

## Completed operator configuration (reported 2026-10-10)

- Moved the PUBLIC Publisher into `devfactory-reviewer-trust` without changing
  repository ID or the private DevFactory repository.
- Added `deenkids7-dev` as organization Member with base Read.
- GitHub confirmed `deenkids7-dev` has no Publisher push/admin permission.
- Installed OpenAI ChatGPT Codex Connector for the organization with repository
  access scoped to Publisher. Authenticated write was successfully tested.
- Configured `reviewer-b-publish`: `deenkids7-dev` required reviewer,
  Prevent self-review enabled, administrator bypass disabled, protected
  branches only. Owner explicitly confirmed saving these settings.
- Owner confirmed adding both `Verify independent runner` and
  `Verify fail-closed attestation logic` to protected `main` required
  checks, with up-to-date checks and no bypass. Direct branch protection
  detail GET returned HTTP 403 for the connector; this particular fact
  is based on owner UI and explicit confirmation, not an API-level read.

**UNVERIFIED:** no secret-free deployment hold-and-release test has run;
the protected environment gate must not be represented as proven operational.
The current trusted branch contains only a smoke test, not a production
Publisher; reviewer evidence is synthetic.

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

## Updated free local engine status — 2026-10-10

The 7B and 14B local Ollama models were actually run with hard-coded synthetic
diffs on PUBLIC GitHub-hosted runners without paid model APIs. This does not
contradict the lack of an independently authorized PRIVATE-code reviewer.
The signed evidence pipeline, GitHub App token purposes, and live-read
transport remain dormant/prototype. No keys, source transfer or publisher
permissions have been provisioned. Repo-level CodeRabbit automatic reviews
have been explicitly disabled, but a third-party billing account, if any,
must be controlled independently in that provider's own settings.
