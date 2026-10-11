import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {prepareNonAuthorizingNativeComment} from '../candidate/native-comment-contract.mjs';
const sha='a'.repeat(40),base='b'.repeat(40),diff='c'.repeat(64);
const report=Buffer.from('PRIVATE_CANARY_TEST_ONLY');
const p=()=>({
 target:{repository:'deenkids7-dev/deenkids',repositoryId:1282086207,
  prNumber:899,headSha:sha,baseSha:base,diffSha256:diff},
 staticDisposition:'INCONCLUSIVE',blockingFindings:0,
 semanticAnalysisCompleted:false,independentReviewVerified:false,
 approvalAuthorized:false,publishEvent:null,
 staticReportBytes:Buffer.from(report)
});
const runId='gh-38140023698-1';
const good=()=>prepareNonAuthorizingNativeComment({
 privatePreflight:p(),expectedHeadSha:sha,runId});
test('native COMMENT contains only non-authorizing digests and fixed facts',()=>{
 const x=good();
 assert.equal(x.event,'COMMENT');
 assert.equal(x.evidenceClass,'NATIVE_COMMENT_ONLY');
 assert.equal(x.approvalAuthorized,false);
 assert.equal(x.independentReviewVerified,false);
 assert.match(x.body,/Result: INCONCLUSIVE/);
 assert.match(x.body,/^<!-- devfactory-reviewer-b-comment-only:v1:/);
 assert.doesNotMatch(x.body,/devfactory-reviewer-b-native:v1:/);
 assert.match(x.body,/HUMAN_GO/);
 assert.match(x.body,new RegExp(sha));
 assert.ok(x.body.includes(createHash('sha256').update(report).digest('hex')));
 assert.doesNotMatch(x.body,/PRIVATE_CANARY_TEST_ONLY/);
 assert.equal(x.prNumber,899);
});
test('no malformed preflight is accepted as native comment source',()=>{
 for(const patch of [
  {staticDisposition:'PASS'},{blockingFindings:1},{semanticAnalysisCompleted:true},
  {independentReviewVerified:true},{approvalAuthorized:true},{publishEvent:'APPROVE'},
  {target:{...p().target,headSha:'b'.repeat(40)}},
  {target:{...p().target,repository:'other/repo'}},
  {target:{...p().target,diffSha256:'bad'}},
  {target:{...p().target,repositoryId:42}},
  {staticReportBytes:null}
 ]){
  const input={...p(),...patch};
  assert.throws(()=>prepareNonAuthorizingNativeComment({
    privatePreflight:input,runId,expectedHeadSha:sha
  }),/NATIVE_COMMENT_UNTRUSTED_PREFLIGHT/);
 }
});
test('bad run ID, HEAD and missing preflight always refuse',()=>{
 for(const id of ['gh-0-1','gh-1-0','bad','gh-1-1\nsecret']){
  assert.throws(()=>prepareNonAuthorizingNativeComment({
   privatePreflight:p(),runId:id,expectedHeadSha:sha
  }),/NATIVE_COMMENT_UNTRUSTED_PREFLIGHT/);
 }
 assert.throws(()=>prepareNonAuthorizingNativeComment({
   privatePreflight:null,runId,expectedHeadSha:sha
 }),/NATIVE_COMMENT_UNTRUSTED_PREFLIGHT/);
});
