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
