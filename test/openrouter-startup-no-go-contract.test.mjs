/**
 * Non-authorizing regression contract for REAL protected OpenRouter path.
 * No mock provider "success" can turn this offline CI into a spend grant.
 * Never connects to GitHub, OpenRouter, PostgreSQL or the Runner.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessAuthenticatedOpenRouterSpendAuthorization as gate}
  from '../scripts/openrouter-only-spend-gate.mjs';

const file=p=>readFileSync(new URL(p,import.meta.url),'utf8');
const real=file('../scripts/protected-real-openrouter-review.mjs');
const spend=file('../scripts/openrouter-only-spend-gate.mjs');
const sql=file('../sql/reviewer_b_shadow_central_pg_v1.sql');

const assertBlocked=result=>{
  assert.equal(result.status,'BLOCKED');
  assert.equal(result.verified,false);
  assert.equal(result.maySpend,false);
  assert.equal(result.mayReserve,false);
  assert.equal(result.mayRetryAmbiguousRequest,false);
  assert.equal(result.reason,
    'OPENROUTER_MONTHLY_RESERVATION_AND_IDEMPOTENCY_NOT_IMPLEMENTED');
  assert.equal(result.monthlyCapEur,15);
  assert.equal(Object.isFrozen(result),true);
};

test('real paid spend gate refuses without evidence',()=>{
  assertBlocked(gate());
});
test('forged billing proof, user consent and fake approval cannot grant spend',()=>{
  for(const f of [
    {verified:true,maySpend:true,mayReserve:true},
    {providerBillingAuthenticated:true,accountCoverageAuthenticated:true,
      fxAuthenticated:true,independentReviewerApproved:true},
    {status:'APPROVED',HUMAN_GO:true,MERGE_GO:true,ZERO_CURSOR_GO:true},
    {verified:true,providerStatements:[{signed:true}],
      monthlyCapEur:15000000},
    {prNumber:73,headSha:'a'.repeat(40),approved:true},
    {retryAmbiguousRequest:true,releaseHeldCharge:true,rolledOver:true},
  ])assertBlocked(gate(f));
});
test('paid real protected path must consume the real gate before model POST',()=>{
  assert.match(real,/from '\.\/openrouter-only-spend-gate\.mjs'/);
  assert.match(real,/assessAuthenticatedOpenRouterSpendAuthorization\(/);
  assert.match(real,/if\(budget\.verified!==true\|\|budget\.maySpend!==true\)/);
  assert.match(real,/deny\('CLOUD_OPENROUTER_ONLY_BUDGET_NOT_PROVEN'\)/);
  const budgetIndex=real.indexOf("stage='OPENROUTER_BUDGET'");
  const modelIndex=real.indexOf("stage='OPENROUTER'");
  assert.ok(budgetIndex>=0&&modelIndex>budgetIndex);
  assert.ok(real.indexOf('executeCompleteOpenRouterSemanticReview({',modelIndex)>
    modelIndex);
});
test('consent and unique service request are not substituted for billing gate',()=>{
  assert.match(real,/fetchAndVerifyOwnerCloudConsent\(/);
  assert.match(real,/fetchAndVerifyUniqueOpenRouterServiceRequest\(/);
  const consent=real.indexOf("stage='CONSENT'");
  const unique=real.indexOf("stage='UNIQUE_REQUEST'");
  const budget=real.indexOf("stage='OPENROUTER_BUDGET'");
  assert.ok(consent>=0&&consent<unique&&unique<budget);
});
test('real paid Publisher is not wired to shadow witness or synthetic ledger',()=>{
  assert.doesNotMatch(real,/openrouter-shadow-(?:audit|witness|billing|provider|evidence|admission|readonly)/);
});
test('shadow ledger does not grant real spend or authenticated billing',()=>{
  assert.match(sql,/may_spend boolean,provider_billing_authenticated boolean/);
  assert.match(sql,/SHADOW_MONTH_NOT_PROVISIONED/);
  assert.match(sql,/SHADOW_DUPLICATE_OR_AMBIGUOUS/);
  assert.match(sql,/FOR UPDATE NOWAIT/);
  assert.match(sql,/READ COMMITTED|read committed/);
  assert.match(sql,/15000000/);
  assert.doesNotMatch(spend,/status:\s*'APPROVED'|maySpend:\s*true/);
});
test('real cost grant remains a deliberate non-implementing stub',()=>{
  assert.match(spend,/OPENROUTER_MONTHLY_RESERVATION_AND_IDEMPOTENCY_NOT_IMPLEMENTED/);
  assert.match(spend,/No external provider calls, key reads, state mutations or scheduling/);
  assert.doesNotMatch(spend,/openrouter-shadow-/);
});


/**
 * OpenRouter's documented management GET data is informative but does not
 * authenticate an unbilled/pending liability upper bound or future execution.
 * These are deliberate local adversarial objects, not HTTP requests.
 */
test('management API observations cannot grant budget authorization',()=>{
  assertBlocked(gate({
    managementReadsObserved:true,
    keyListing:{path:'/api/v1/keys',status:200,
      data:[{hash:'a'.repeat(64),usage_monthly:0,disabled:false}]},
    activity:{path:'/api/v1/activity',status:200,
      data:[{date:'2026-10-19',usage:0,requests:0}]},
    credits:{path:'/api/v1/credits',status:200,
      data:{total_credits:100,total_usage:0}},
    verified:true,maySpend:true,
  }));
});
test('default-workspace keys GET cannot certify full workspace inventory',()=>{
  for(const candidate of [
    {workspaceList:['default'],allKeysCovered:true},
    {keyListComplete:true,include_disabled:true,offset:0},
    {workspaces:[{id:'default'}],workspacePaginationExhausted:true},
  ])assertBlocked(gate(candidate));
});
test('last 30 completed UTC days activity cannot prove today or next POST',()=>{
  for(const candidate of [
    {activityRange:'last_30_completed_utc_days',amountPending:0},
    {lastCompletedDay:'2026-10-19',asOfDay:'2026-10-20',
      todayUsageGuaranteedZero:true},
    {activityRequests:0,noUnbilledProviderTraffic:true},
  ])assertBlocked(gate(candidate));
});
test('credit balances and key monthly limits are not global EUR authorization',()=>{
  for(const candidate of [
    {remainingCredits:100.5,currency:'USD',eurRemaining:15},
    {keyLimits:[3,10],keyCurrency:'USD',monthlyCapEur:15},
    {keyAUsageUsd:0,keyBUsageUsd:0,accountWidePendingEur:0},
  ])assertBlocked(gate(candidate));
});
test('post-timeout unknown billing cannot be cleared by zero known charges',()=>{
  for(const candidate of [
    {lastHttpStatus:504,knownChargeUsd:0,providerSettled:true},
    {requestReset:true,mayRetryAmbiguousRequest:true},
    {lastHttpStatus:429,retryAfter:5,mayRetry:true},
    {providerUsageLagSeconds:120,unsettledUpperBoundEur:0},
  ])assertBlocked(gate(candidate));
});
test('disabled and rotated keys can still have unaccounted prior charges',()=>{
  for(const candidate of [
    {disabledKeysExcluded:true,allLiabilitiesSettled:true},
    {lastKeyDeleted:true,knownSpendEur:0},
    {managementKeyPresent:true,inventoryAuthenticated:true},
  ])assertBlocked(gate(candidate));
});
test('unsigned FX and public price tables cannot mint a EUR reservation',()=>{
  for(const candidate of [
    {usdToEurRate:1.0,fxAuthenticated:true,mayReserve:true},
    {modelPricesCurrent:true,maximumOutputTokens:1024,
      worstCaseEur:0.0001,maySpend:true},
    {providerZdr:true,providerBillingAuthenticated:true,
      concurrencyGuaranteed:true},
  ])assertBlocked(gate(candidate));
});
test('owner and Reviewer B approval claims remain separate from spending',()=>{
  for(const candidate of [
    {HUMAN_GO:true,MERGE_GO:true,ZERO_CURSOR_GO:true},
    {independentReviewerState:'APPROVED',headSha:'a'.repeat(40)},
    {ownerConsentVerified:true,model:'qwen/qwen3-coder-30b-a3b-instruct'},
    {serviceRequestUnique:true,firstAttempt:true,maySpend:true},
  ])assertBlocked(gate(candidate));
});
test('cross-month and cross-key simulated exhaustion never rolls credit grant',()=>{
  for(const candidate of [
    {monthUtc:'2026-11',previousMonthOutstandingEur:0,mayReserve:true},
    {allClients:'same-postgres',shadowProposalRecorded:true,
      providerBillingAuthenticated:true},
    {budgetLimitEur:15,accountTotalKnownEur:0,unresolvedUsd:0,
      maySpend:true},
  ])assertBlocked(gate(candidate));
});
