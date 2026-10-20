# DevFactory Reviewer B — offline OpenRouter liability stress test

**20 October 2026 — PR #73 — SYNTHETIC ONLY / DRAFT / NO SPEND.**

## Scope and immutable safety boundary

This work adds a **standalone mock-only exposure calculator**,
\`scripts/openrouter-shadow-billing-reconciliation-offline.mjs\`, and
\`test/openrouter-shadow-billing-reconciliation-offline.test.mjs\`.
It does not call OpenRouter or GitHub, read a secret, connect to a database,
persist a reservation, compute a trusted FX rate, or grant spend rights.
The real \`openrouter-only-spend-gate.mjs\` remains **BLOCKED**. Reviewer B
does not obtain a real provider invoice or an independent service identity.

The sole input is a bounded serialized JSON document with exact keys:
\`month_utc\`, \`coverage:"illustrative-only"\`,
\`currency:"EUR"\`, and \`records\` (1–500 records). Each mock record has
exactly \`request_id\`, \`key_role\` (\`development\` or \`reviewer_b\`),
\`state\` (\`settled\`, \`pending\` or \`ambiguous\`),
\`already_billed_micro_eur\` and \`unsettled_upper_micro_eur\`.
All amounts are **hypothetical micro-euros**, never authenticated
provider charges. The synthetic test switch must be explicitly enabled.

## Conservative scenario algorithm

- Every unique request ID is counted once across both mock key roles.
  Duplicate IDs, unknown roles, injected extra fields, malformed JSON,
  negative/noninteger money and invalid state combinations fail closed.
- For every record, hypothetical exposure is
  **already billed + still-held maximum liability**. This can
  deliberately overcount overlapping invoice/hold exposures. A timeout,
  HTTP 5xx or disconnection means **ambiguous**, not \`settled\` or
  \`no charge\`; the unreconciled hold remains.
- \`pending\` / \`ambiguous\` require a positive held amount and always
  return \`mayRetryAmbiguousRequest:false\`. A \`settled\` request
  must have no hold. The model never releases money or retries anything.
- The **15,000,000 micro-EUR ceiling** exists only to detect hypothetical
  overexposure. Even a simulation under cap returns
  \`status:"BLOCKED"\`, \`maySpend:false\`, \`mayReserve:false\`,
  \`verified:false\`, \`providerBillingAuthenticated:false\`,
  \`accountCoverageAuthenticated:false\` and \`fxAuthenticated:false\`.

This model aggregates two named roles, but that is **not proof of
coverage of all real OpenRouter keys, workspaces, account charges,
other services or unsettled invoice adjustments**. A maliciously
crafted mock \`settled\` entry cannot become genuine evidence.
The EUR denomination is illustrative; real provider spend may
be USD, must use an independently trusted FX quote, time bounds,
conservative rounding, and durable reconciliation.

## Production blockers still missing

1. Trusted, authenticated billing ledger covering all relevant keys
   and pending/settled charges, with uncertainty bounds and audit trail.
2. Durable cross-process idempotency / reservation coordinator and
   a provider request identity that cannot be silently retried.
3. Protected receiver service with authentic transport identity,
   pinned/revocable verification keys and nonbypassable SQL transaction
   boundaries, including expiry at COMMIT.
4. Authenticated USD/EUR rate source and documented upper-bound rounding.
5. Independently verified data privacy / ZDR, cost permission for exact
   model and HEAD, official Reviewer B assessment, HUMAN_GO,
   exact-SHA MERGE_GO, and later ZERO_CURSOR_GO after local MSI requalification.

**NO-GO SPEND / NO-GO MERGE / NO-GO DEPLOY / NO-GO RUNNER.**
