import test from 'node:test';
import assert from 'node:assert/strict';
import {inspect} from 'node:util';
import {publishNonAuthorizingNativeReview} from '../scripts/protected-native-comment-publisher.mjs';
const sha='a'.repeat(40),base='b'.repeat(40),diff='c'.repeat(64),num=899;
const api='https://api.github.com/repos/deenkids7-dev/deenkids/pulls/899';
const tokenRead='read-only-token-12345678',tokenWrite='write-only-token-98765432';
const preflight=()=>({
 target:{repository:'deenkids7-dev/deenkids',repositoryId:1282086207,
  prNumber:num,headSha:sha,baseSha:base,diffSha256:diff},
 staticDisposition:'INCONCLUSIVE',blockingFindings:0,
 semanticAnalysisCompleted:false,independentReviewVerified:false,
 approvalAuthorized:false,publishEvent:null,
 staticReportBytes:Buffer.from('PRIVATE_FILE_AND_REPORT_TEST_ONLY')
});
const reply=(url,obj,opts={})=>({
 url,redirected:false,status:opts.status||200,
 headers:{get:k=>k==='content-type'?'application/json':null},
 body:new Response(JSON.stringify(obj)).body
});
function emulator({previousReview=null,head=sha,postOverride=null}={}){
 let posted=null,calls=[],counter=0;
 const fetchImpl=async(url,options)=>{
  calls.push({url,method:options.method,token:options.headers.Authorization,
   payload:options.method==='POST'?JSON.parse(options.body):null});
  if(url===api&&options.method==='GET'){
   return reply(url,{number:num,state:'open',merged_at:null,
    head:{sha:head,repo:{id:1282086207,full_name:'deenkids7-dev/deenkids'}},
    base:{repo:{id:1282086207,full_name:'deenkids7-dev/deenkids'}}});
  }
  if(url===api+'/reviews?per_page=100&page=1'&&options.method==='GET')
    return reply(url,[...(previousReview?[previousReview]:[]),...(posted?[posted]:[])]);
  if(url===api+'/reviews'&&options.method==='POST'){
   counter++;
   const body=JSON.parse(options.body);
   const review={id:98765,state:'COMMENTED',user:{
    id:340237276,login:'devfactory-reviewer-b[bot]'},
    commit_id:body.commit_id,body:body.body,pull_request_url:api,
    submitted_at:'2026-10-11T12:45:00Z'};
   posted=postOverride?{...review,...postOverride}:review;
   return reply(url,posted,{status:200});
  }
  throw Error('UNEXPECTED_ENDPOINT:'+url);
 };
 const request=({extra={}}={})=>({
  privatePreflight:preflight(),runId:'gh-38140023698-1',
  expectedHeadSha:sha,readToken:tokenRead,writeToken:tokenWrite,
  approvedProtectedComment:true,fetchImpl,...extra
 });
 return {fetchImpl,calls,request,posts:()=>counter};
}
test('protected native comment is written with separate scoped token and read back',async()=>{
 const mock=emulator();
 const res=await publishNonAuthorizingNativeReview(mock.request());
 assert.equal(res.nativeReviewId,98765);
 assert.equal(res.prNumber,899);
 assert.equal(res.event,'COMMENTED');
 assert.equal(res.evidenceClass,'NATIVE_COMMENT_ONLY');
 for(const field of ['independentReviewVerified','approvalAuthorized',
   'reviewerPass','attestedReportVerified','humanGoVerified'])
   assert.equal(res[field],false);
 assert.equal(mock.posts(),1);
 const post=mock.calls.filter(x=>x.method==='POST');
 assert.equal(post.length,1);
 assert.equal(post[0].token,'Bearer '+tokenWrite);
 assert.equal(post[0].payload.event,'COMMENT');
 assert.equal(post[0].payload.commit_id,sha);
 assert.match(post[0].payload.body,/INCONCLUSIVE/);
 assert.doesNotMatch(post[0].payload.body,/PRIVATE_FILE_AND_REPORT_TEST_ONLY/);
 for(const call of mock.calls.filter(x=>x.method==='GET'))
  assert.equal(call.token,'Bearer '+tokenRead);
 assert.doesNotMatch(JSON.stringify(res),/PRIVATE_FILE_AND_REPORT_TEST_ONLY/);
 assert.doesNotMatch(inspect(res),/PRIVATE_FILE_AND_REPORT_TEST_ONLY/);
});
test('preflight permission cannot be obtained from an untrusted boolean-like value',async()=>{
 for(const value of [undefined,null,false,'true',1,{}]){
  const mock=emulator();
  await assert.rejects(()=>publishNonAuthorizingNativeReview(mock.request({
   extra:{approvedProtectedComment:value}
  })),/NATIVE_COMMENT_NOT_AUTHORIZED/);
  assert.equal(mock.calls.length,0);
 }
});
test('separate scoped read and write tokens are mandatory',async()=>{
 for(const extra of [{readToken:null},{writeToken:null},
  {writeToken:tokenRead},{readToken:'***'},{writeToken:'***'}]){
  const mock=emulator();
  await assert.rejects(()=>publishNonAuthorizingNativeReview(mock.request({extra})),
   /NATIVE_COMMENT_INVALID_SCOPED_TOKENS/);
  assert.equal(mock.calls.length,0);
 }
});
test('pre-existing Reviewer B bot native review blocks duplicate publication',async()=>{
 const existing={id:7,user:{id:340237276,login:'devfactory-reviewer-b[bot]'},
  state:'COMMENTED',commit_id:sha,pull_request_url:api,body:'prior',
  submitted_at:null};
 const mock=emulator({previousReview:existing});
 await assert.rejects(()=>publishNonAuthorizingNativeReview(mock.request()),
   /NATIVE_COMMENT_EXISTING_REVIEW_BLOCK/);
 assert.equal(mock.posts(),0);
});
test('stale PR HEAD denies publication before a write token is used',async()=>{
 const mock=emulator({head:'b'.repeat(40)});
 await assert.rejects(()=>publishNonAuthorizingNativeReview(mock.request()),
   /REVIEWS_HEAD_CHANGED_OR_UNVERIFIED/);
 assert.equal(mock.posts(),0);
});
test('server cannot silently change COMMENT into APPROVED',async()=>{
 const mock=emulator({postOverride:{state:'APPROVED'}});
 await assert.rejects(()=>publishNonAuthorizingNativeReview(mock.request()),
   /NATIVE_COMMENT_POST_IDENTITY_UNVERIFIED/);
 assert.equal(mock.posts(),1);
});
test('server cannot claim a fake bot identity in returned review',async()=>{
 const mock=emulator({postOverride:{
  user:{id:1234,login:'attacker'},state:'COMMENTED'}});
 await assert.rejects(()=>publishNonAuthorizingNativeReview(mock.request()),
   /NATIVE_COMMENT_POST_IDENTITY_UNVERIFIED/);
});
test('incomplete or static block preflight cannot publish any native review',async()=>{
 for(const patch of [{blockingFindings:1,staticDisposition:'FAIL'},
  {target:{...preflight().target,diffSha256:'bad'}},
  {semanticAnalysisCompleted:true}]){
  const mock=emulator();
  await assert.rejects(()=>publishNonAuthorizingNativeReview(mock.request({
   extra:{privatePreflight:{...preflight(),...patch}}
  })),/NATIVE_COMMENT_UNTRUSTED_PREFLIGHT/);
  assert.equal(mock.posts(),0);
 }
});
