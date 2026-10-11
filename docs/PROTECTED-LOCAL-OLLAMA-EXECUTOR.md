# Protected local Ollama review executor — non-production bridge

## What actually exists

The following modules are now integrated for a prospective, free local
semantic review **after a true PRIVATE GitHub App read has been authorized**:

1. `runReadOnlyReviewPreflight`: obtains immutable, authenticated private
   PR metadata + diff; runs deterministic fail-only static audit. Its
   `privateSemanticPlan` property is deliberately nonenumerable and the
   complete private diff is suppressed from JSON, spread and Node inspection.
2. `prepareOfflineOllamaCandidate`: validates the exact PRIVATE repository
   ID, base/head/diff digest and changed paths. It creates bounded
   local-only JSON requests without granting model submission or approval.
3. `executeLocalOllamaReview`: refuses to call even loopback unless a
   separately reviewed protected operator context sets
   `approvedLocalPrivateProcessing===true`. The only URL is
   `http://127.0.0.1:11434/api/chat`; redirects, changed origin, oversized,
   malformed and incomplete responses all fail closed. No external API token,
   cloud inference, model registration or new scheduler.
4. `validateOfflineOllamaCompletion`: checks actual response metadata,
   token/context limits, finding path and added-line anchors; recomputes
   fingerprints. A clean output remains **INCONCLUSIVE**.

**Every result keeps**
`independentReviewVerified:false`,
`approvalAuthorized:false`, and `publishEvent:null`.
The private report stays nonenumerable, with copy-on-access.

## Not deployed or permitted

- The protected PRIVATE App PEM and its repository-scoped permissions have
  not been provisioned; neither the public CI runner nor the DevFactory MSI
  is allowed to substitute a personal GitHub PAT.
- There is NO live Ollama process attached to protected `main`, and no
  acceptance benchmark/known-good model digest proven for production.
- The TRUE signed independent-witness requirement, verified GitHub/Sigstore
  binding to a private report, unique native GitHub review ID and canonical
  HUMAN_GO are separate unfinished gates. No private PR merge is authorized.
- Local processing approval MUST come from reviewed trusted workflow policy
  + approved protected environment. Never derive it from `workflow_dispatch`
  text, model output, user-uploaded PR, source comments or an operator-like
  string. Nothing in this module creates that approval on its own.

## Validation

The test suite uses only synthetic PR diffs and a fake loopback server.
It verifies private-source redaction, immutable SHA binding, actual
local request payload, refusal without local processing authorization,
malformed transport, duplicate/fake findings and negative cases.
The test suite exercises an end-to-end synthetic metadata → static audit →
local semantic report path, but **not a live private-code review**.

Operator preference: no recurring API fees, no new third reviewer identity,
and no parallel Merge Executor. Hardware runtime/runner minutes and model
downloads still have costs or resource limits; no free pricing guarantee.
