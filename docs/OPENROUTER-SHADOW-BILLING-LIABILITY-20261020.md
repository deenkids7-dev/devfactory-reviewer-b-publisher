# DevFactory Reviewer B — offline OpenRouter liability stress test

**20 October 2026 — PR #73 — SYNTHETIC ONLY / DRAFT / NO SPEND.**

## Scope and immutable safety boundary

This work adds a **standalone mock-only exposure calculator**,
`scripts/openrouter-shadow-billing-reconciliation-offline.mjs`, and
`test/openrouter-shadow-billing-reconciliation-offline.test.mjs`.
It does not call OpenRouter or GitHub, read a secret, connect to a database,
persist a reservation, compute a trusted FX rate, or grant spend rights.
The real `openrouter-only-spend-gate.mjs` remains **BLOCKED**. Reviewer B
does not obtain a real provider invoice or an independent service identity.

The sole input is a bounded serialized JSON document with exact keys:
`month_utc`, `coverage:"illustrative-only"`,
`currency:"EUR"`, and `records` (1–500 records). Each mock record has
exactly `request_id`, `key_role` (`development` or `reviewer_b`),
`state` (`settled`, `pending` or `ambiguous`),
`already_billed_micro_eur` and `unsettled_upper_micro_eur`.
All amounts are **hypothetical micro-euros**, never authenticated
provider charges. The synthetic test switch must be explicitly enabled.

## Conservative scenario algorithm

- Every unique request ID is counted once across both mock key roles.
  Duplicate IDs, unknown roles, injected extra fields, malformed JSON,
  negative/noninteger money and invalid state combinations fail closed.
- For every record, hypothetical exposure is
  **already billed + still-held maximum liability**. This can
  deliberately overcount overlapping invoice/hold exposures. A timeout,
  HTTP 5xx or disconnection means **ambiguous**, not `settled` or
  `no charge`; the unreconciled hold remains.
- `pending` / `ambiguous` require a positive held amount and always
  return `mayRetryAmbiguousRequest:false`. A `settled` request
  must have no hold. The model never releases money or retries anything.
- The **15,000,000 micro-EUR ceiling** exists only to detect hypothetical
  overexposure. Even a simulation under cap returns
  `status:"BLOCKED"`, `maySpend:false`, `mayReserve:false`,
  `verified:false`, `providerBillingAuthenticated:false`,
  `accountCoverageAuthenticated:false` and `fxAuthenticated:false`.

This model aggregates two named roles, but that is **not proof of
coverage of all real OpenRouter keys, workspaces, account charges,
other services or unsettled invoice adjustments**. A maliciously
crafted mock `settled` entry cannot become genuine evidence.
The EUR denomination is illustrative; real provider spend may
be USD, must use an independently trusted FX quote, time bounds,
conservative rounding, and durable reconciliation.

## Additional offline USD/EUR FX stress simulation

The separate `scripts/openrouter-shadow-fx-reconciliation-offline.mjs`
takes **serialized synthetic JSON only**, under the same test-only switch.
Its paired test file is
`test/openrouter-shadow-fx-reconciliation-offline.test.mjs`.
It is deliberately **not imported by the real Publisher or spend gate**.
The GitHub synthetic admission workflow runs the negative cases.

A mock document requires the exact top-level keys `coverage`,
`month_utc`, `observed_at`, `fx_quote`, `entries`. The quote has
`source:"synthetic-fixture"`, `pair:"USD/EUR"`, decimal **integer
strings** `numerator` and `denominator`, `issued_at` and
`expires_at`. Each record has a unique `request_id`, the
`development` or `reviewer_b` mock key role, a `charge_month_utc`
matching the scenario month, one of `settled`/`pending`/`ambiguous`,
and integer-string `billed_micro_usd` and `held_micro_usd`.

For each record and **each** billed/held component independently, the
simulated conversion is:

```text
micro_eur = ceil(micro_usd * numerator / denominator)
total_micro_eur = sum(converted_billed + converted_held)
```

The calculator uses arbitrary-precision integers, prevents duplicate
request IDs across key roles, rejects inconsistent settlement states
and caps what it exposes as a safe numeric diagnostic. An ambiguous or
pending charge keeps its *entire* mock liability on hold (plus partial
invoicing) and **cannot be retried**. Missing, future or expired mock
quotes and windows greater than 5 minutes fail closed. The code compares
**fixture-supplied** timestamps only; it makes **no claim of actual
current quote freshness**, source identity or authenticity. Modelled
month mismatch is refused rather than auto-releasing earlier holds.

This is **not FX hedging**, no guarantee that the numerator/denominator
is a valid economic rate, and no trusted authenticated rate source. An
attacker can fabricate a quote, the entries, their billed state, and
the list of all keys. Therefore an apparently low converted liability
must **never** unlock paid OpenRouter. Across-period liabilities,
real provider billing delays, charge reversals, the source of
provider request IDs, and a durable idempotency ledger remain unproven.
Every result is still `BLOCKED / maySpend:false /
mayReserve:false / mayRetryAmbiguousRequest:false` and does not
create a reservation or merge/Runner permission.

## Cross-month mock provider reconciliation (no real invoices)

A further **offline-only, deterministic fixture** is implemented in
**scripts/openrouter-shadow-provider-reconciliation-offline.mjs** and tested in
**test/openrouter-shadow-provider-reconciliation-offline.test.mjs**.
The existing synthetic GitHub Actions workflow exercises this module.
It is not imported into any billable path.

The fixture has one uniquely identified intention per request, its declared
key role (development or reviewer_b), initiation UTC month, simulated state
(settled, pending, ambiguous) and positive held micro-USD for unresolved
outcomes. Separate mock invoice lines carry globally unique line IDs,
request IDs, billing UTC months and unsigned integer-string micro-USD
amounts. All inputs are **unverified fixture data**, not authenticated
evidence about OpenRouter invoices, credits, provider identity or account
coverage.

The review model does not discard potential liability:
- An ambiguous **September** request continues to hold its full upper
  bound in **October**, until an independently established final result.
- A partial invoice received the next month is **added to** the held
  upper-bound amount. A timeout or missing provider record is not
  permission to retry or release that hold.
- An invoice without a matching request is an orphan and blocks the
  simulated reconciliation instead of being ignored.
- Duplicate request IDs across both key roles, duplicate invoice IDs,
  invoice months before request creation, future billing periods,
  invalid monetary strings, overflow and contradictory states are denied.
- A supposedly settled mock request without invoice evidence is denied,
  rather than treated as free. This is a conservative fixture rule,
  **not a factual claim about all genuinely zero-cost requests**.
- Even a matching mock ledger remains BLOCKED with all spend, reserve,
  retry, provider verification and account-completeness permissions false.

The sums remain in hypothetical **USD micro-units**. They are NOT
converted into real EUR liabilities or compared with the proposed
EUR 15 synthetic ceiling. They prove neither all-key coverage nor
provider authenticity. Charge reversals, refunds, adjustments,
zero-cost settlements, partial invoice delivery, clock skew, retention,
across-account enumeration, provider request identity, real FX,
provider credit expiry and post-timeout settlement remain unresolved.
A trusted billing evidence source, durable idempotency and a separately
approved reconciliation protocol are mandatory before real spending.


## Offline attempt-lifecycle and no-retry contract

The preparatory module `scripts/openrouter-shadow-attempt-lifecycle-offline.mjs`
and its dedicated test file model a **hypothetical event sequence only**.
They are run in the isolated synthetic GitHub Actions workflow. Inputs
are bounded serialized JSON fixtures with strictly sequential event
numbers and exact role, request, attempted dispatch, HEAD and UTC-month
identity. This is neither a service nor a trusted durable event store.

For every fixture request, the permitted illustrative phases are:

1. `reserved` — a local *simulation* of a planned attempt.
2. `dispatch_recorded` — **one hypothetical** dispatch-intent event;
   this code does **not** send any request.
3. `outcome_unknown` after dispatch — preserve uncertainty, do not
   re-dispatch or refund any hold.
4. `settled_fixture` only after recorded dispatch, possibly from unknown
   status, but with no authentic provider receipt.
5. `cancelled_before_dispatch` only from reserved; cancellation after a
   possible dispatch is forbidden.

Second dispatches (including after simulated settlement), duplicate
request or attempt IDs across roles, resurrecting a cancellation, stale
event sequence, forged HEAD/role/attempt identifiers and a backwards
UTC-month transition are all denied. Every result is **BLOCKED** with
`maySpend:false`, `mayReserve:false`, `verified:false`,
`mayRetryAmbiguousRequest:false`, and
`durableIdempotencyVerified:false`.

**Critical limit:** strict parsing and replay of caller-supplied fixtures
does not establish authentic persistence, atomicity, crash durability or
cross-machine serialization. A malicious caller can fabricate or omit
the entire event history. A future authorized production component
would require a centrally provisioned durable database with a UNIQUE
provider-account/request-id pair, write-before-send intent, atomic
CAS transitions, protected credentials, reliable acknowledgement
provenance and explicit recovery for ambiguous attempts. It must be
impossible for two dispatchers to act on different stale copies.
Even a unique database request ID cannot guarantee provider-side
idempotency unless the provider documents and enforces compatible
semantics; do not automatically retry requests whose charge is unknown.

This PR deliberately neither deploys this coordinator nor calls a
provider API, and does not lift any financial, deployment, merge or
Runner gate.

## Real PostgreSQL16 *synthetic* dispatch-risk tombstones

The additive file `sql/reviewer_b_attempt_tombstone_synthetic_v1.sql`
defines a **separate**, inactive-by-default schema
`reviewer_b_attempt_shadow`. It is executed in an **ephemeral
PostgreSQL 16.4 CI service only**, not on a real Publisher database.
Two NOLOGIN principals isolate a privileged definer and a restricted
test invoker. No account key, network credential or production login
is provisioned. Public execution privileges and invoker table access
are revoked; all state changes must use reviewed functions.

The immutable identities `request_id` and `attempt_id` are both
globally unique across UTC months and across mock key roles. Database
constraints enforce a four-state monotonic record:

- `registered`: an intent exists; no outbound request has happened.
- `dispatch_may_have_occurred`: one atomic, committed **risk
  tombstone** should precede *any* hypothetical network send.
- `outcome_unknown`: a potential dispatch has uncertain billing;
  no replay, cancellation or automatic financial release.
- `cancelled_before_dispatch`: cancellation while no dispatch
  marker exists; request ID cannot be recreated.

`record_dispatch_risk` uses a PostgreSQL row lock
`FOR UPDATE NOWAIT` and a state-checked CAS. One independent
connection cannot create another dispatch marker once the first has
committed. Failed/ambiguous database writes are never an invitation
to send the request. `register_synthetic_attempt` refuses reused
request/attempt IDs even when callers change roles or calendar months.

The separate test `test/openrouter-shadow-attempt-postgres-real.test.mjs`
runs inside the existing restricted PostgreSQL 16.4 multi-client
workflow. It verifies real connection-level privilege isolation,
database lock contention, rollback visibility, reconnect/restart
persistence within the *ephemeral* CI instance, duplicate/reforged
identity rejection, invalid repeat dispatches, denial after unknown
outcomes, and cancellation strictly before a dispatch marker.
The tested entrypoints always return `may_spend=false` and
`may_dispatch=false`; the test creates **no actual paid request**.

**Important transactional limit:** a hypothetical external send after
a successful SQL function response but **before COMMIT** would still
be unsafe; rollback would remove the marker. In real use, the caller
would have to prove that the marker committed durably **before egress**,
handle lost COMMIT acknowledgements as permanently uncertain, and
never retry an unknown billing outcome. Database-only uniqueness does
not establish upstream provider idempotency or exactly-once execution.
A separate protected dispatcher, authenticated invoice reconciliation
and independent threat review are mandatory. The schema is deliberately
**not linked** to the Publisher, actual budget coordinator, paid API,
secret-bearing receiver, Runner or deployment scripts.

## Recovery observation after a lost COMMIT acknowledgment (synthetic)

The same test-only PostgreSQL tombstone migration now includes the
SECURITY DEFINER function
`reviewer_b_attempt_shadow.observe_attempt_after_uncertain_commit`.
It requires immutable request ID, attempt ID and HEAD; runs only with
READ COMMITTED isolation; reads status using `FOR SHARE NOWAIT` to
reject conflicting in-flight updates; exposes no raw table permissions
to the restricted test invoker; and returns `may_spend=false`,
`may_dispatch=false`, `may_retry=false` for **every** outcome,
including matching, REGISTERED, missing, cancelled or ambiguous.
A wrong ID/HEAD and invalid isolation produce fail-closed observations.

The PostgreSQL 16 multi-client integration test models two cases:
- A COMMIT is successfully acknowledged by PostgreSQL, then the test
  deliberately discards that response at the application boundary
  (synthetic lost acknowledgment). An independent newly authenticated
  session reads the persisted `dispatch_may_have_occurred` marker
  and cannot create a second marker or a new attempt under that ID.
- A transaction is rolled back before its dispatch marker commits.
  The read-only recovery function sees `registered`, but **still**
  grants neither dispatch nor retry: without trusted evidence,
  the caller cannot infer whether an external action occurred.
  An in-flight UPDATE lock causes the recovery read to fail immediately
  instead of silently trusting stale data.

**Boundaries:** This does NOT simulate a real dropped TCP COMMIT reply,
database restart/failover, lost durable writes, operator/superuser
modification, network egress to OpenRouter, actual invoice identity,
or provider-supported idempotency. In particular a client must **not**
use the underlying synthetic registration/dispatch function as a
"retry" after a lost acknowledgment: the recovery function alone
does not enforce a production dispatcher protocol. Real deployment
requires durable COMMIT verification, independent provider billing,
authentic identity, full-key coverage, lost-ACK incident controls and
a separately reviewed protected dispatch service.

## Isolated PostgreSQL backend-loss regression (synthetic, no provider)

The existing PostgreSQL 16 multi-connection test also terminates a
**separate disposable test backend** with `pg_terminate_backend` while
the backend holds an UNCOMMITTED dispatch-risk marker. The database
should roll back that connection's transaction. An independent
authenticated recovery session then observes the preexisting
`registered` row, but receives `may_retry=false`,
`may_dispatch=false`, and `may_spend=false`.

This directly tests a server-side session termination in an
**ephemeral GitHub Actions PostgreSQL service**. It is not a test
of production database failover, persistent-volume loss, WAL durability,
network egress timing, actual OpenRouter billing, or
provider-side idempotency. A `registered` row or a missing row is
not evidence that no external call occurred. Future recovery must
quarantine uncertain attempts pending authenticated reconciliation
and explicit policy, never issue a duplicate paid request.

## Isolated PostgreSQL quarantine for unresolved mock provider charges

The additive, **synthetic-only** migration
`sql/reviewer_b_attempt_quarantine_synthetic_v1.sql` extends the
existing `reviewer_b_attempt_shadow` schema in the **disposable**
PostgreSQL 16 GitHub Actions database. It requires the pre-existing
tombstone migration and does **not** create a competing ledger or
connect to the actual Publisher, OpenRouter, Runner or paid service.

The `quarantines` table contains exactly one immutable quarantine
entry per synthetic request ID, linked by a database foreign key to
the original attempt. The protected
`quarantine_synthetic_attempt` function binds the request,
attempt ID and exact HEAD, locks the existing risk row with
`FOR UPDATE NOWAIT`, and only accepts requests already in
`dispatch_may_have_occurred` or `outcome_unknown`.
`registered` and `cancelled_before_dispatch` cannot fabricate a
provider-risk quarantine entry. A second quarantine for the same
request is refused. This does not confer any right to send again,
resume a request, or release money.

The `unverified_evidence` table stores **untrusted test fixtures**
under quarantined request IDs, with globally unique evidence IDs
and SHA-256-format digests. The single
`record_unverified_evidence_fixture` function only accepts
`mock_invoice`, `mock_timeout`, `mock_adjustment` or
`mock_absence` and labels the provenance
`unverified-fixture`. A duplicate ID/digest or a proposed
`provider-authenticated` category is rejected. No claim is
validated against an OpenRouter signature, API, billing statement,
actual key or provider accounting ledger. A fixture saying
`mock_absence` must **never** imply a zero-dollar outcome.

These tables have no release, refund, DELETE, promote-to-verified or
dispatch entrypoint for the restricted test role. Both functions
are `SECURITY DEFINER`, owned by a NOLOGIN test principal;
PUBLIC EXECUTE and direct table permissions are revoked.
Every return value keeps `may_spend=false`,
`may_dispatch=false`, `may_retry=false`,
`may_release_hold=false`, and evidence additionally reports
`provider_authenticated=false`.

The existing multi-connection PostgreSQL16 integration test now
checks denied direct access, conflicting quarantines under
`NOWAIT`, rollback of uncommitted quarantine, unique identity
and digest behavior, spoofed fixture authentication, negative
amounts, absent/mismatched requests, and the continuing prohibition
on dispatch from the underlying read-only recovery observer.

**Known limits:** This is an isolation/coordination test, not
authenticated billing reconciliation or a production-approved
incident workflow. The untrusted mock evidence can be fabricated,
omitted or incomplete. It does not establish ZDR, invoice completeness
across all keys, trusted FX, real refund behavior, end-to-end
exactly-once provider semantics, durable database failover,
operator/superuser trust, or account-wide cost authorization.
Actual holds must remain unresolved unless a future independently
audited billing/authorization workflow explicitly proves and
permits changes; this PR does not implement that future release.

## Composite PostgreSQL identity binding in quarantine (synthetic)

An additional defense-in-depth constraint now binds each quarantine
record to the **same (request_id, attempt_id, exact head_sha)** as the
underlying synthetic attempt. The test-only quarantine migration adds
a PostgreSQL UNIQUE triplet constraint to the pre-existing attempts
table, then uses an explicit **composite foreign key** from
`reviewer_b_attempt_shadow.quarantines` to that triplet.

This protects against a future function implementation error that
could otherwise record a correct request ID alongside an incorrect
attempt ID or HEAD. Unlike a procedural equality check, the relation
is checked by PostgreSQL on direct INSERT/UPDATE as well. Foreign-key
checks are **not** proof against a privileged database owner who
can alter schema or disable constraints; operator and superuser trust
remain outside this fixture's security guarantees.

The existing PostgreSQL 16 integration test uses isolated
administrator permissions to deliberately attempt invalid direct
quarantine INSERTs and UPDATEs and mutation of the referenced
parent attempt identity. Mismatches must fail with SQLSTATE
`23503`; a legitimate quarantine with matching identifiers
still succeeds, and all recovery outputs continue to deny
spend/dispatch/retry. The synthetic test does not contact
OpenRouter or validate provider invoices.

A cryptographic-looking digest or a successful relational join
does **not** authenticate an invoice, demonstrate full account/key
coverage, establish exact provider-side idempotency, or justify
releasing a held amount. All production financial and human
approval gates remain unchanged.

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
