# Low-cost DeepSeek Reviewer B plan — NOT DEPLOYED

**Status: prototype. No live provider billing, external source transfer, or review publishing.**

Official rates, consulted 2026-10-10: https://api-docs.deepseek.com/quick_start/pricing/
Official completion API: https://api-docs.deepseek.com/api/create-chat-completion/

## One model, not a competing model router

- Default: DeepSeek V4.1 Flash, API model ID: deepseek-flash.
- Optional manually chosen benchmark model: deepseek-v4-pro.
- Legacy deepseek-chat/deepseek-reasoner aliases must be rejected.
- One deliberately selected model per authorized run. No implicit fallback,
  routing engine, scheduler or additional DevFactory authority.
- Only the independent, security-reviewed analyzer may hold its API key.

## Price scenario (USD, peak, uncached input, no caching discounts)

Official peak token rates per million:
- Flash: input $0.30, output $1.20.
- V4 Pro: input $1.32, output $3.96.
- Off-peak prices are half; rates are subject to change.

For 60,000 input tokens and 2,048 output tokens:
- Flash: (60,000×0.30 + 2,048×1.20)/1,000,000 = $0.0204576 per pass.
- 100 PR × 1 pass = $2.04576 (illustration only).
- 100 PR × 3 passes = $6.13728 (illustration only).
- Pro: (60,000×1.32 + 2,048×3.96)/1,000,000 = $0.08731008 per pass.

These figures exclude any runner cost, retries, errors, provider rate
changes and extra context. They are NOT a guaranteed invoice.

## Existing code gate (not authority to send private source)

candidate/deepseek-review-contract.mjs is a PURE, non-network candidate.
It builds one JSON-mode request, verifies exact model IDs and response
completion, enforces caller-supplied token ceilings and indicative peak
cost. Default estimated per-call ceiling is $0.10.

A trustworthy tokenizer, fresh rates, real operator-approved monthly budget
and atomic spending control are ALL STILL MISSING. Do not create another
DevFactory budget manager or silently auto-recharge. Inference is NOT enabled.

## Private-source exposure gate

The target deenkids7-dev/deenkids is PRIVATE. An authorization to develop
software does not authorize sending its code to an external AI provider.
The human operator must explicitly approve the destination, applicable
data-processing terms, confidentiality and cost cap BEFORE any live call.

No inference on the MSI or in public Publisher PR CI. Do not expose private
source, raw diffs, review reports, App keys or API credentials in public
GitHub Actions logs, commits or artifacts. Treat PR text as untrusted data.

## Quality tests and fail-closed status

Begin with 10–20 synthetic benchmark PRs with known bugs, malformed diffs,
prompt injection, incorrect HEAD, risky workflow changes and incomplete
model responses. Report bug detection and false-positive rates.

- A real blocking finding => provisional FAIL.
- No findings => INCONCLUSIVE, never automatic PASS.
- Missing, stale, malformed or untrusted provenance => BLOCKED.
- Cryptographic signature alone is NOT proof of independent execution.
- Only a separately authenticated analysis identity, trusted GitHub PR
  scope, canonical HUMAN_GO and independently validated native review
  could eventually authorize a review or a protected merge.

## Mandatory operator steps before production

1. Independent security review of the exact Publisher PR #2 code/workflow.
2. Independently authorized promotion of the NO-SECRET environment approval
   probe onto protected main and real hold/release verification.
3. Approve provider, confidentiality/data transfer and monthly ceiling.
4. In separate isolated trust domains, provision provider API credentials,
   analyzer signing key, Publisher native RSA key and GitHub App JWT key.
   Never place keys in chat, on MSI, in public CI, issues or artifacts.
5. Reverify the App installation ID, narrowly scoped permissions and
   canonical Issue HUMAN_GO authority (Issues:Read requires operator approval).
6. Test real independently witnessed dry runs BEFORE publishing native reviews.
7. Reconcile the exact draft DevFactory PR #900 native evidence verifier.

**STOP:** No real keys or subscription needed yet. The current candidate is
testable for free; it cannot approve or merge DevFactory PRs #898–#901.
