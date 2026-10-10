import test from 'node:test';
import assert from 'node:assert/strict';
import { assessIndependentReviewCandidates } from '../candidate/independent-review-candidates.mjs';
const head='a'.repeat(40),prev='b'.repeat(40);
const parameters=(reviews,extra={})=>({
 repository:'devfactory-reviewer-trust/devfactory-reviewer-b-publisher',
 prNumber:2,expectedHeadSha:head,
 eligibleReviewerLogins:['external-security-reviewer'],
 reviews,...extra
});
const rev=(login,commit=head,state='APPROVED',id=100,when='2026-10-10T15:00:00Z')=>({
 id,state,commit_id:commit,submitted_at:when,
 user:{login,id:id+1000,type:'User'}
});
test('a separately named external account is NOT proof of independent reviewer provenance',()=>{
 const v=assessIndependentReviewCandidates(parameters([
  rev('external-security-reviewer')
 ]));
 assert.equal(v.freshExternalAccountApprovalPresent,true);
 assert.equal(v.externalAccountApprovalCandidates.length,1);
 assert.equal(v.securityReviewVerified,false);
 assert.equal(v.githubOriginAuthenticated,false);
 assert.equal(v.actualHumanIndependenceVerified,false);
 assert.equal(v.approvalAuthorized,false);
 assert.equal(v.publishEvent,null);
});
test('blocked co-owned GitHub accounts and bot types cannot masquerade as independent',()=>{
 for(const login of ['devfactory-reviewer-service','deenkids7-dev'])
  assert.throws(()=>assessIndependentReviewCandidates(parameters([],{
   eligibleReviewerLogins:[login]
  })),/REVIEW_CANDIDATES_SCOPE_INVALID/);
 assert.throws(()=>assessIndependentReviewCandidates(parameters([
  {...rev('external-security-reviewer'),user:{
   login:'external-security-reviewer',id:99,type:'Bot'
  }}
 ])),/REVIEW_CANDIDATES_GITHUB_FORMAT_INVALID/);
});
test('stale HEAD, changed request and non-approved review never appear fresh',()=>{
 for(const reviews of [
  [rev('external-security-reviewer',prev)],
  [rev('external-security-reviewer',head,'COMMENTED')],
  [rev('external-security-reviewer',head,'CHANGES_REQUESTED')]
 ]){
  const v=assessIndependentReviewCandidates(parameters(reviews));
  assert.equal(v.freshExternalAccountApprovalPresent,false);
 }
 assert.throws(()=>assessIndependentReviewCandidates(parameters([],{
  expectedHeadSha:'notasha'
 })),/REVIEW_CANDIDATES_SCOPE_INVALID/);
});
test('a newer changes-requested or dismissed review overrides older approval',()=>{
 const earlier=rev('external-security-reviewer',head,'APPROVED',100,'2026-10-10T15:00:00Z');
 const later=rev('external-security-reviewer',head,'CHANGES_REQUESTED',101,'2026-10-10T15:10:00Z');
 const got=assessIndependentReviewCandidates(parameters([earlier,later]));
 assert.equal(got.freshExternalAccountApprovalPresent,false);
 const d=assessIndependentReviewCandidates(parameters([earlier,{
  ...later,state:'DISMISSED'
 }]));
 assert.equal(d.freshExternalAccountApprovalPresent,false);
});
test('a plain GitHub comment or forged reviewer input never counts',()=>{
 const got=assessIndependentReviewCandidates(parameters([
  rev('external-security-reviewer',head,'COMMENTED')
 ]));
 assert.equal(got.freshExternalAccountApprovalPresent,false);
 assert.throws(()=>assessIndependentReviewCandidates(parameters([{
  ...rev('external-security-reviewer'),id:0
 }])),/REVIEW_CANDIDATES_GITHUB_FORMAT_INVALID/);
});
