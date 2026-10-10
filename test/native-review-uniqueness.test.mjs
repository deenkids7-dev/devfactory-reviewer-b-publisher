import test from 'node:test';
import assert from 'node:assert/strict';
import { assessNativeReviewUniqueness }
  from '../candidate/native-review-uniqueness.mjs';

const sha='a'.repeat(40);
const uri='https://api.github.com/repos/deenkids7-dev/deenkids/pulls/898';
const review=(id,userId=340237276,login='devfactory-reviewer-b[bot]',body='untrusted',extra={})=>({
  id, user:{id:userId,login},commit_id:sha,body,
  state:'COMMENTED',pull_request_url:uri,...extra
});
const observed=(reviews,targetHeadSha=sha)=>({reviews,targetHeadSha});
const context=(reviews,targetHeadSha=sha)=>({
  observed:observed(reviews,targetHeadSha),prNumber:898,currentHeadSha:sha
});

test('absence of any review NEVER grants authority',()=>{
  const result=assessNativeReviewUniqueness(context([]));
  assert.equal(result.blocked,false);
  assert.equal(result.approvalAuthorized,false);
  assert.equal(result.independentReviewVerified,false);
});
test('unsigned existing bot review blocks another review',()=>{
  const result=assessNativeReviewUniqueness(context([review(5)]));
  assert.equal(result.blocked,true);
  assert.equal(result.reason,'BOT_ALREADY_REVIEWED_THIS_HEAD');
  assert.equal(result.existing[0].reviewId,5);
  assert.equal(result.existing[0].hasNativeMarker,false);
});
test('existing bot native marker also blocks repeat',()=>{
  const result=assessNativeReviewUniqueness(context([
    review(5,340237276,'devfactory-reviewer-b[bot]',
      '<!-- devfactory-reviewer-b-native:v1:YWJj -->\nSigned fixture')
  ]));
  assert.equal(result.blocked,true);
  assert.equal(result.existing[0].hasNativeMarker,true);
});
test('unrelated human review does not count as Reviewer B',()=>{
  const result=assessNativeReviewUniqueness(context([
    review(7,1234,'deenkids7-dev','Approved')
  ]));
  assert.equal(result.blocked,false);
  assert.equal(result.approvalAuthorized,false);
});
test('review on stale HEAD does not count as the current HEAD',()=>{
  const result=assessNativeReviewUniqueness(context([
    review(7,340237276,'devfactory-reviewer-b[bot]','old',{
      commit_id:'b'.repeat(40)
    })
  ]));
  assert.equal(result.blocked,false);
});
test('wrong bot login is not accepted as native reviewer',()=>{
  const result=assessNativeReviewUniqueness(context([
    review(9,340237276,'impostor[bot]')
  ]));
  assert.equal(result.blocked,false);
});
test('duplicate GitHub review IDs fail closed',()=>{
  assert.throws(()=>assessNativeReviewUniqueness(context([review(5),review(5)])),
    /REVIEW_UNIQUENESS_DATA_UNTRUSTED/);
});
test('review list must be bound to latest trusted HEAD',()=>{
  assert.throws(()=>assessNativeReviewUniqueness(context([], 'b'.repeat(40))),
    /REVIEW_UNIQUENESS_CONTEXT_INVALID/);
});
test('unexpected repository review URL fails closed',()=>{
  assert.throws(()=>assessNativeReviewUniqueness(context([
    review(5,340237276,'devfactory-reviewer-b[bot]','body',{
      pull_request_url:'https://other.example'
    })
  ])),/REVIEW_UNIQUENESS_DATA_UNTRUSTED/);
});
test('non-array or oversized review listing fails closed',()=>{
  assert.throws(()=>assessNativeReviewUniqueness({
    observed:{reviews:null,targetHeadSha:sha},
    prNumber:898,currentHeadSha:sha
  }),/REVIEW_UNIQUENESS_CONTEXT_INVALID/);
  assert.throws(()=>assessNativeReviewUniqueness(context(
    Array.from({length:251},(_,i)=>review(i+1))
  )),/REVIEW_UNIQUENESS_CONTEXT_INVALID/);
});
