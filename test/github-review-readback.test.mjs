import test from 'node:test';
import assert from 'node:assert/strict';
import { readNativeReviews } from '../candidate/github-review-readback.mjs';

const TOKEN='ghs_SYNTHETIC_ONLY_NOT_REAL_TOKEN';
const repo='deenkids7-dev/deenkids';
const url=p=>`https://api.github.com/repos/${repo}/pulls/898/reviews?per_page=100&page=${p}`;
const head='a'.repeat(40);
const review=(id,changes={})=>({
  id,user:{id:340237276,login:'devfactory-reviewer-b[bot]'},
  commit_id:head,state:'COMMENTED',
  submitted_at:'2026-10-10T12:00:00Z',
  pull_request_url:`https://api.github.com/repos/${repo}/pulls/898`,
  body:'Synthetic review - not independent',...changes
});
function response(target,body,overrides={}){
  const bytes=Buffer.from(JSON.stringify(body));
  return {
    url:overrides.url||target,status:overrides.status||200,redirected:false,
    headers:new Headers({'content-type':overrides.contentType||'application/json'}),
    body:new ReadableStream({start(c){c.enqueue(bytes);c.close();}})
  };
}
function mock(pageSets,opts={}){
  const calls=[];
  const fetchImpl=async (target,req)=>{
    calls.push({target,req});
    if(opts.fail)throw Error('secret: '+TOKEN);
    const page=Number(new URL(target).searchParams.get('page'));
    return response(target,pageSets[page-1]||[],opts);
  };
  return {calls,fetchImpl};
}
function context(fetchImpl){
  return {prNumber:898,expectedHeadSha:head,
    installationToken:TOKEN,fetchImpl};
}
test('reads bounded native reviews from private API, without review authority',async()=>{
  const fake=mock([[review(1)]]);
  const result=await readNativeReviews(context(fake.fetchImpl));
  assert.equal(result.reviews.length,1);
  assert.equal(result.reviews[0].id,1);
  assert.equal(result.reviews[0].user.id,340237276);
  assert.ok(Object.isFrozen(result.reviews[0]));
  assert.ok(Object.isFrozen(result.reviews[0].user));
  assert.equal(result.approvalAuthorized,false);
  assert.equal(result.independentReviewVerified,false);
  assert.equal(fake.calls[0].target,url(1));
  assert.equal(fake.calls[0].req.method,'GET');
  assert.equal(fake.calls[0].req.redirect,'error');
  assert.equal(fake.calls[0].req.headers.Authorization,'Bearer '+TOKEN);
  assert.ok(!JSON.stringify(result).includes(TOKEN));
});
test('paginates without truncating when exactly 100 reviews',async()=>{
  const first=Array.from({length:100},(_,i)=>review(i+1));
  const fake=mock([first,[review(101)]]);
  const result=await readNativeReviews(context(fake.fetchImpl));
  assert.equal(result.reviews.length,101);
  assert.deepEqual(fake.calls.map(x=>x.target),[url(1),url(2)]);
});
test('rejects >250 review records rather than silently discarding evidence',async()=>{
  const pages=[
    Array.from({length:100},(_,i)=>review(i+1)),
    Array.from({length:100},(_,i)=>review(i+101)),
    Array.from({length:100},(_,i)=>review(i+201))
  ];
  const fake=mock(pages);
  await assert.rejects(()=>readNativeReviews(context(fake.fetchImpl)),
    /REVIEWS_TOO_MANY/);
});
test('cannot accept a duplicate review ID across pages',async()=>{
  const fake=mock([Array.from({length:100},(_,i)=>review(i+1)),[review(1)]]);
  await assert.rejects(()=>readNativeReviews(context(fake.fetchImpl)),
    /REVIEWS_ITEM_UNTRUSTED/);
});
test('rejects forged author or malformed PR URL',async()=>{
  const fake=mock([[review(1,{pull_request_url:'https://other.example/898'})]]);
  await assert.rejects(()=>readNativeReviews(context(fake.fetchImpl)),
    /REVIEWS_ITEM_UNTRUSTED/);
});
test('redirect, unexpected media and HTTP failure are denied',async()=>{
  for(const opts of [
    {url:'https://attacker.example/reviews'},{contentType:'text/html'},
    {status:301}
  ]){
    const fake=mock([[review(1)]],opts);
    await assert.rejects(()=>readNativeReviews(context(fake.fetchImpl)),
      /REVIEWS_GITHUB_RESPONSE_REJECTED/);
  }
});
test('network error cannot leak token into caller-facing error',async()=>{
  const fake=mock([],{fail:true});
  await assert.rejects(()=>readNativeReviews(context(fake.fetchImpl)),
    e=>e.message==='REVIEWS_GITHUB_REQUEST_FAILED'&&!e.message.includes(TOKEN));
});
test('path and auth tokens must match expected repository',async()=>{
  const fake=mock([[review(1)]]);
  for(const data of [
    {prNumber:'898'}, {prNumber:0},
    {expectedHeadSha:'BAD'},
    {installationToken:'bad header\nBearer'}
  ]){
    await assert.rejects(()=>readNativeReviews({
      ...context(fake.fetchImpl),...data
    }),/REVIEWS_INVALID_REQUEST/);
  }
  assert.equal(fake.calls.length,0);
});
test('empty reviews cannot grant approval',async()=>{
  const fake=mock([[]]);
  const result=await readNativeReviews(context(fake.fetchImpl));
  assert.equal(result.reviews.length,0);
  assert.equal(result.approvalAuthorized,false);
});
