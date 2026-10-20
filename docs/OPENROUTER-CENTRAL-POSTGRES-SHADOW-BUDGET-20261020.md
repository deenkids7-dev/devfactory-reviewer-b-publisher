# Central PostgreSQL shadow-budget design — NOT LIVE (20 October 2026)

**Status: DRAFT / PREPARATORY / NON-DEPLOYED.** This is not a global
billing proof, a secret-bearing server, or a spend permit. It proposes one
transactional persistence model for Reviewer B across *independent clients*
that all connect to one trusted durable PostgreSQL database.

## Code contract

- `sql/reviewer_b_shadow_central_pg_v1.sql` creates a private
  `reviewer_b_shadow` schema, server-provisioned monthly accounting rows,
  a durable append-only **proposal** table, and a narrowly scoped SQL
  function `propose_exposure(...)`.
- Each call obtains `SELECT ... FOR UPDATE NOWAIT` on the shared UTC
  monthly row. Distinct clients cannot both read the old total and create
  two proposals beyond the limit. Lock contention or a missing period is
  a denial, **not** a reason to retry a billable model request.
- Month selection uses `transaction_timestamp() AT TIME ZONE 'UTC'`
  on the trusted database, not a caller-supplied month. An independently
  authorized operator must provision the monthly row; no auto-rollover.
- Database constraints reject duplicate private `repo + PR + HEAD` or
  reused service comment IDs across *all* periods, including rollover.
  The function conservatively totals proposed upper bounds in integer
  micro-euros, never exceeding **15,000,000 micro-euros per UTC month**;
  it refuses a 501st proposal within one period before writing.
- Malformed models, hashes, actors, run IDs and prices are refused; the
  SQL function is a `SECURITY INVOKER`, not `SECURITY DEFINER`.
  Default SQL privileges are explicitly REVOKED from PUBLIC, and no
  database roles, secrets or network grants are created by the migration.
- All outputs, successful or otherwise, set `may_spend=false` and
  `provider_billing_authenticated=false`. `recorded=true` proves only
  a proposed record exists; it **never** authorizes OpenRouter egress.

## Proof today / what the tests DO NOT prove

The standalone contract test uses only Node.js built-ins and passes under
the existing zero-dependency CI. Actual SQL execution was separately
tested with **PGlite 0.5.10 PostgreSQL WASM** on MSI, including the server
month, rejection without period, duplicate head/comment, 15 EUR bound,
malformed claims, 501st proposal and uniqueness across periods.
The dependency is installed only in a temporary local sandbox; the
Publisher's package.json/workflows/dependency tree remain unchanged.

To rerun the database tests in an isolated local environment:

```powershell
npm install --prefix C:\\temp\\pglite-audit --no-save --ignore-scripts @electric-sql/pglite@0.5.10
$env:SHADOW_PGLITE_ENTRY="C:\\temp\\pglite-audit\\node_modules\\@electric-sql\\pglite\\dist\\index.js"
node --test test/openrouter-central-shadow-sql.test.mjs
```

PGlite uses a single local database process; it **does not validate**
multi-process PostgreSQL locking under real network concurrency.
A security-reviewed multi-connection PostgreSQL integration test with
separate identities must be passed before deployment. No private source
code or real account credentials were used in these test fixtures.

## Remaining blockers — NO-GO

1. **Authentic provider billing:** account-wide pending/settled invoices,
   unknown key spend, charges after HTTP timeouts, billable retries,
   billing lag, currencies and reconciliations are not proven by this ledger.
2. **Authenticated FX:** EUR ceiling cannot be inferred from unauthenticated
   or unbounded USD charges. This schema accepts proposed micro-EUR values
   supplied by a caller and MUST NOT be promoted to a billable permission.
3. **Operator/identity model:** DB deployment, audited role grants, protected
   service-to-service authentication and secret rotation, immutable audit
   history and multiple-client recovery still need external review.
4. **Actual cross-client concurrency:** prove `FOR UPDATE NOWAIT` with
   separate real PostgreSQL connections, kill/failover tests, independent
   period provisioning and no trust in caller-supplied evidence.
5. **Data security:** scoped database, backup/restore, bounded tables,
   monitoring, limits, incident handling and offboarding are not created.
   A database owner or compromised service principal can bypass the
   invocation policy; trusted DB roles are part of the threat model.
6. **Human gates:** exact-head Reviewer B security attestation, owner private
   egress consent, ZDR, `MERGE_GO`, `HUMAN_GO` and `ZERO_CURSOR_GO`
   remain separate and unsatisfied.

**NOT CONNECTED** to Publisher `openrouter-only-spend-gate.mjs`,
`protected-real-openrouter-review.mjs`, any Github Actions workflow,
OpenRouter API endpoint, RunPod or the private DevFactory Runner. The
real Publisher continues to return
`OPENROUTER_MONTHLY_RESERVATION_AND_IDEMPOTENCY_NOT_IMPLEMENTED` and
`maySpend:false`.

**Decision: NO-GO SPEND, NO-GO RUNNER, NO-GO MERGE, NO-GO PUBLISH.**

## Advisory second-IA review and hardening (20 October 2026)

The independent second-IA *technical* review of the staged patch identified
real P2 counter/isolation and calendar rollover hazards, and a test role
assertion mismatch. Corrections in this draft:

- **Isolation**: accept only `READ COMMITTED`. `REPEATABLE READ` and
  `SERIALIZABLE` are explicitly denied, even if a caller presents a valid
  synthetic proposal. The period row now contains `reserved_micro_eur`
  and `proposal_count` counters and is **updated** in the same
  transaction as the proposal insertion, so the period's row version moves.
  Do not silently support stale-snapshot transaction modes.
- **UTC time**: use `clock_timestamp()` rather than the transaction-start
  time for admission. Re-check before insertion and at the end of the write.
  A month boundary during the write raises a fixed exception and aborts the
  complete SQL statement, without retaining a proposal.
- **PUBLIC privilege**: tests inspect `pg_catalog.aclexplode()` for the
  pseudo-role grant (`grantee=0`) instead of confusing it with an ordinary
  role named `public`.
- **Tests**: 5/5 in local PGlite execution, including the two unsupported
  isolation modes and counter consistency. In the ordinary GitHub Actions
  `npm test` run the PGlite integration cases are **skipped**, because
  this PR deliberately leaves the zero-dependency package and workflows
  intact. CI green alone does not validate SQL execution.

A live multi-session PostgreSQL test is still mandatory before any
deployment. This branch **does not implement that test** and must not be
promoted or merged as if it did. This is a shadow proposal prototype only,
not a central billing authentication or transactional spend authorization.
