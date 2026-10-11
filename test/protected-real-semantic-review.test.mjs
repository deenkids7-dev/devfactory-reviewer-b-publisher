import test from 'node:test';
import assert from 'node:assert/strict';
import {inspect} from 'node:util';
import {readFileSync} from 'node:fs';
import {canRunRealSemanticReview,prepareRealSemanticComment,
  publishRealSemanticComment,executeProtectedRealSemanticReview,
  classifyProtectedReviewFailure}
  from '../scripts/protected-real-semantic-review.mjs';

const HEAD='a'.repeat(40),BASE='b'.repeat(40),DIFF='c'.repeat(64);
const RUN='gh-38140023698-1', PR=899;
const URL='https://api.github.com/repos/deenkids7-dev/deenkids/pulls/899';
const READ='test-read-token-98765432',WRITE='test-write-token-12345678';
const env=()=>({
 GITHUB_REPOSITORY:'devfactory-reviewer-trust/devfactory-reviewer-b-publisher',
 GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',
 GITHUB_ACTOR:'devfactory-reviewer-service',
 GITHUB_SHA:'f'.repeat(40),GITHUB_RUN_ID:'38140023698',
 GITHUB_RUN_ATTEMPT:'1',REVIEWER_B_TARGET_PR:'899',
 GITHUB_WORKFLOW_REF:'devfactory-reviewer-trust/devfactory-reviewer-b-publisher/.github/workflows/reviewer-b-private-semantic.yml@refs/heads/main',
 REVIEWER_B_EXPECTED_MODEL:'qwen2.5-coder:7b'
});
const preflight=()=>({
 target:{repository:'deenkids7-dev/deenkids',repositoryId:1282086207,
  prNumber:PR,headSha:HEAD,baseSha:BASE,diffSha256:DIFF},
 staticDisposition:'INCONCLUSIVE',blockingFindings:0,
 approvalAuthorized:false,independentReviewVerified:false,publishEvent:null,
 privateSemanticPlan:{changedPaths:['src/a.mjs']}
});
const report=(findings=[])=>Buffer.from(JSON.stringify({
 schema:'devfactory.reviewer-b.findings.v1',run_id:RUN,
 summary:'A real-model structured report from a PRIVATE test diff.',findings
}));
const local=(findings=[])=>({
 model:'qwen2.5-coder:7b',localModelExecuted:true,
 rawByteCoverageProven:true,originalDiffSha256:DIFF,processedShardCount:2,
 provisionalState:findings.length?'FAIL':'INCONCLUSIVE',
 findingCount:findings.length,localResponseSha256:'d'.repeat(64),
 privateCanonicalReportBytes:report(findings),
 approvalAuthorized:false,independentReviewVerified:false,publishEvent:null
});
const finding=()=>({severity:'high',path:'src/a.mjs',line:4,
 message:'Access check accepts a non-owner',evidence:'Specified test input bypasses guard',
 fingerprint:'e'.repeat(64)});
const prepared=()=>prepareRealSemanticComment({preflight:preflight(),local:local(),runId:RUN});
test('protected execution requires exact trusted main, workflow, actor and MODEL',()=>{
 assert.equal(canRunRealSemanticReview(env()),true);
 assert.equal(canRunRealSemanticReview({...env(),GITHUB_EVENT_NAME:'push',
  REVIEWER_B_TARGET_PR:'899'}),true);
 assert.equal(canRunRealSemanticReview({...env(),GITHUB_EVENT_NAME:'issue_comment',
  REVIEWER_B_TARGET_PR:'901',REVIEWER_B_EXPECTED_HEAD:HEAD}),true);
 assert.equal(canRunRealSemanticReview({...env(),GITHUB_EVENT_NAME:'issue_comment',
  REVIEWER_B_TARGET_PR:'901',REVIEWER_B_EXPECTED_HEAD:'invalid'}),false);
 assert.equal(canRunRealSemanticReview({...env(),GITHUB_EVENT_NAME:'issue_comment',
  REVIEWER_B_TARGET_PR:'901',REVIEWER_B_EXPECTED_HEAD:null}),false);
 for(const patch of [
  {GITHUB_ACTOR:'deenkids7-dev'},{GITHUB_REF:'refs/heads/dev'},
  {GITHUB_EVENT_NAME:'pull_request'},
  {GITHUB_EVENT_NAME:'push',REVIEWER_B_TARGET_PR:'898'},
  {GITHUB_WORKFLOW_REF:'attacker/other'},
  {REVIEWER_B_TARGET_PR:'0'},{REVIEWER_B_TARGET_PR:'899;rm'},
  {REVIEWER_B_EXPECTED_MODEL:'gemini-expensive'},
  {GITHUB_SHA:'invalid'}
 ])assert.equal(canRunRealSemanticReview({...env(),...patch}),false);
});
test('no protected environment key means no PRIVATE source or external HTTP',async()=>{
 let calls=0;
 for(const patch of [{},{REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM:null}]){
  const result=await executeProtectedRealSemanticReview({env:{...env(),...patch},
   fetchImpl:async()=>{calls++;throw Error('DO_NOT_CALL');}});
  assert.deepEqual(result,{ok:false,code:'CREDENTIAL_NOT_PROVISIONED'});
 }
 assert.equal(calls,0);
});
test('real LOCAL response is represented as COMMENT, never approval',()=>{
 const p=prepared();
 assert.equal(p.event,'COMMENT');
 assert.equal(p.approvalAuthorized,false);
 assert.equal(p.independentReviewVerified,false);
 assert.match(p.body,/INCONCLUSIVE/);
 assert.match(p.body,/Full-diff local model parts completed: 2/);
 assert.match(p.body,/Real local response SHA-256/);
 assert.match(p.body,/NO automated PASS/);
 assert.doesNotMatch(p.body,/event:\s*APPROVE/);
});
test('protected native Qwen report declares QUICK or DEEP and Gemini is NEVER a required gate',()=>{
 const quick=prepareRealSemanticComment({
  preflight:preflight(),local:{...local(),reviewMode:'QUICK',
   geminiAdvisoryRecommended:false},runId:RUN
 });
 assert.match(quick.body,/Local review lane: QUICK/);
 assert.match(quick.body,/Gemini supplemental review: NOT_REQUIRED/);
 const deep=prepareRealSemanticComment({
  preflight:preflight(),local:{...local(),reviewMode:'DEEP',
   geminiAdvisoryRecommended:true},runId:RUN
 });
 assert.match(deep.body,/Local review lane: DEEP/);
 assert.match(deep.body,/Gemini supplemental review: SUGGESTED_NON_BLOCKING/);
 assert.match(deep.body,/NO automated PASS or merge authority/);
 assert.equal(quick.approvalAuthorized,false);
 assert.equal(deep.independentReviewVerified,false);
 for(const patch of [
  {reviewMode:'SKIP'},
  {reviewMode:['DEEP']},
  {geminiAdvisoryRecommended:'true'},
  {reviewMode:'QUICK',geminiAdvisoryRecommended:true},
 ])assert.throws(()=>prepareRealSemanticComment({
  preflight:preflight(),local:{...local(),...patch},runId:RUN
 }),/REAL_SEMANTIC_PROOF_INVALID/);
});
test('actual model finding is bounded, attributed to changed file, still not PASS',()=>{
 const p=prepareRealSemanticComment({preflight:preflight(),
   local:local([finding()]),runId:RUN});
 assert.match(p.body,/PROVISIONAL_FINDINGS/);
 assert.match(p.body,/src\/a.mjs:4/);
 assert.match(p.body,/Access check accepts a non-owner/);
 assert.equal(p.approvalAuthorized,false);
});
test('LOW nonblocking model finding remains INCONCLUSIVE but is not discarded',()=>{
 const f={...finding(),severity:'low'};
 const observed={...local([f]),provisionalState:'INCONCLUSIVE'};
 const p=prepareRealSemanticComment({preflight:preflight(),local:observed,runId:RUN});
 assert.match(p.body,/INCONCLUSIVE/);
 assert.match(p.body,/LOW src\/a.mjs:4/);
 assert.equal(p.approvalAuthorized,false);
});
test('unsafe model message cannot inject mentions, tags or markdown code fences',()=>{
 const f={...finding(),message:'@everyone <script> bad'+String.fromCharCode(96)+'payload'};
 const p=prepareRealSemanticComment({preflight:preflight(),
   local:local([f]),runId:RUN});
 assert.doesNotMatch(p.body,/@everyone|<script>|bad\x60payload/);
 assert.match(p.body,/＠|_everyone/);
});
test('reject fake or stale model, body, report, path and authority before publication',()=>{
 const patches=[
  {local:{...local(),localModelExecuted:false}},
  {local:{...local(),model:'qwen3:8b'}},
  {local:{...local(),approvalAuthorized:true}},
  {local:{...local(),privateCanonicalReportBytes:Buffer.from('not json')}},
  {local:{...local(),findingCount:7}},
  {local:local([{...finding(),path:'secrets/other'}])},
  {preflight:{...preflight(),target:{...preflight().target,headSha:'x'.repeat(40)}}},
  {preflight:{...preflight(),independentReviewVerified:true}},
  {runId:'evil'}
 ];
 for(const patch of patches)assert.throws(()=>prepareRealSemanticComment({
  preflight:preflight(),local:local(),runId:RUN,...patch
 }),/REPORT_|SEMANTIC_|REAL_|PROOF_|UNSAFE/);
});
const reply=(url,obj)=>({url,redirected:false,status:200,
 headers:{get:key=>key==='content-type'?'application/json':null},
 body:new Response(JSON.stringify(obj)).body});
function emulator({changedHead=false,override=null,existing=null}={}){
 let post=null,n=0,calls=[];
 const fetchImpl=async(url,opt)=>{
  calls.push({url,method:opt.method,auth:opt.headers.Authorization});
  if(url===URL&&opt.method==='GET')
   return reply(url,{number:PR,state:'open',merged_at:null,
    head:{sha:changedHead?'f'.repeat(40):HEAD,
     repo:{id:1282086207,full_name:'deenkids7-dev/deenkids'}},
    base:{repo:{id:1282086207,full_name:'deenkids7-dev/deenkids'}}});
  if(url===URL+'/reviews?per_page=100&page=1'&&opt.method==='GET')
    return reply(url,[...(existing?[existing]:[]),...(post?[post]:[])]);
  if(url===URL+'/reviews'&&opt.method==='POST'){
    n++;
    const payload=JSON.parse(opt.body);
    post={id:1234567,state:'COMMENTED',commit_id:payload.commit_id,
      body:payload.body,pull_request_url:URL,
      user:{id:340237276,login:'devfactory-reviewer-b[bot]'},
      submitted_at:'2026-10-11T18:00:00Z',...override};
    return reply(url,post);
  }
  throw Error('WRONG_HTTP_ENDPOINT');
 };
 return {fetchImpl,calls,posts:()=>n};
}
const args=(em,other={})=>({plan:prepared(),readToken:READ,writeToken:WRITE,
 approvedProtectedPublication:true,fetchImpl:em.fetchImpl,...other});
test('Gemini findings: missing or mistyped report fields are explicitly denied',()=>{
 const examples=[
   {summary:undefined}, {summary:null}, {summary:42},
   {summary:[]}, {summary:''}, {summary:' '.repeat(3)},
   {summary:'X'.repeat(2001)}
 ];
 for(const change of examples){
   const raw=JSON.parse(report().toString('utf8'));
   Object.assign(raw,change);
   const candidate={...local(),privateCanonicalReportBytes:
     Buffer.from(JSON.stringify(raw))};
   assert.throws(()=>prepareRealSemanticComment({
     preflight:preflight(),local:candidate,runId:RUN
   }),/REAL_SEMANTIC_REPORT_MISMATCH/);
 }
 for(const invalid of [
   {message:null}, {message:2}, {message:[]}, {message:' '},
   {message:'X'.repeat(501)},
   {evidence:null}, {evidence:4}, {evidence:[]},
   {evidence:' '},{evidence:'X'.repeat(1001)},
   {fingerprint:['e'.repeat(64)]}
 ]){
   const findingValue={...finding(),...invalid};
   const candidate=local([findingValue]);
   assert.throws(()=>prepareRealSemanticComment({
     preflight:preflight(),local:candidate,runId:RUN
   }),/REPORT_FINDING_INVALID/);
 }
});
test('real PRIVATE semantic report is published exactly as native COMMENTED',async()=>{
 const em=emulator();
 const result=await publishRealSemanticComment(args(em));
 assert.equal(result.code,'REAL_REVIEW_COMMENT_VERIFIED');
 assert.equal(result.reviewId,1234567);
 assert.equal(result.approvalAuthorized,false);
 assert.equal(em.posts(),1);
 assert.equal(em.calls.filter(c=>c.method==='POST')[0].auth,'Bearer '+WRITE);
 assert.ok(em.calls.filter(c=>c.method==='GET')
  .every(c=>c.auth==='Bearer '+READ));
 assert.doesNotMatch(JSON.stringify(result),/PRIVATE_TEST_SECRET/);
 assert.doesNotMatch(inspect(result),/PRIVATE_TEST_SECRET/);
});
test('Gemini: null or malformed native POST response fails closed',async()=>{
 for(const invalid of [null,undefined,{}]){
  const em=emulator();
  await assert.rejects(()=>publishRealSemanticComment(args(em,{
   fetchImpl:async(url,opt)=>{
    if(url===URL+'/reviews'&&opt.method==='POST')return invalid;
    return em.fetchImpl(url,opt);
   }
  })),/SEMANTIC_POST_REJECTED/);
 }
});
test('cannot POST when human protected environment authorization is absent',async()=>{
 const em=emulator();
 for(const value of [undefined,false,'true',1,null]){
  await assert.rejects(()=>publishRealSemanticComment(args(em,{
   approvedProtectedPublication:value})),/SEMANTIC_PUBLISH_DENIED/);
 }
 assert.equal(em.calls.length,0);
});
test('live HEAD drift, prior bot review, wrong bot and fake APPROVED fail closed',async()=>{
 const cases=[
  [emulator({changedHead:true}),/REVIEWS_HEAD_CHANGED/],
  [emulator({existing:{id:99,commit_id:HEAD,state:'COMMENTED',
   user:{id:340237276,login:'devfactory-reviewer-b[bot]'},
   pull_request_url:URL,body:'older',submitted_at:null}}),/SEMANTIC_ALREADY_REVIEWED/],
  [emulator({override:{state:'APPROVED'}}),/SEMANTIC_POST_UNVERIFIED/],
  [emulator({override:{user:{id:100,login:'bad-bot'}}}),/SEMANTIC_POST_UNVERIFIED/]
 ];
 for(const [em,pattern] of cases)
  await assert.rejects(()=>publishRealSemanticComment(args(em)),pattern);
});

test('security: protected workflow never logs raw credentials, model errors or source',()=>{
 const source=readFileSync(new globalThis.URL(
  '../scripts/protected-real-semantic-review.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(source,/console\.(?:error|warn|debug|info)\s*\(/);
 assert.match(source,/return fail\(classifyProtectedReviewFailure\(stage,error\)\)/);
});
test('protected LIVE stage classifier leaks no secret or private paths',()=>{
 const timeout=classifyProtectedReviewFailure('LOCAL_MODEL',
   Error('LOCAL_MODEL_REQUEST_TIMEOUT'));
 assert.equal(timeout,'REAL_REVIEW_LOCAL_MODEL_LOCAL_MODEL_REQUEST_TIMEOUT');
 const known=classifyProtectedReviewFailure('LOCAL_MODEL',
   Error('OLLAMA_COMPLETION_UNVERIFIED'));
 assert.equal(known,'REAL_REVIEW_LOCAL_MODEL_OLLAMA_COMPLETION_UNVERIFIED');
 const unknown=classifyProtectedReviewFailure('NATIVE_POST',
   Error('PRIVATE_FILENAME=/home/user/key.pem?token=SECRET'));
 assert.equal(unknown,'REAL_REVIEW_NATIVE_POST_FAILED_CLOSED');
 const forgedStage=classifyProtectedReviewFailure(
   'SECRET_USER_CONTROLLED_STAGE',Error('OLLAMA_COMPLETION_UNVERIFIED'));
 assert.equal(forgedStage,'REAL_REVIEW_UNKNOWN_OLLAMA_COMPLETION_UNVERIFIED');
 assert.doesNotMatch([known,unknown,forgedStage].join(' '),
   /PRIVATE_FILENAME|SECRET|key\.pem|\/home\/user/);
 for(const x of [undefined,null,{},[],{message:'OLLAMA_COMPLETION_UNVERIFIED'}])
   assert.equal(classifyProtectedReviewFailure('LOCAL_MODEL',x),
     'REAL_REVIEW_LOCAL_MODEL_FAILED_CLOSED');
});
test('issue request expected exact HEAD verified before any local model inference',()=>{
 const source=readFileSync(new globalThis.URL(
  '../scripts/protected-real-semantic-review.mjs',import.meta.url),'utf8');
 const preflight=source.indexOf('await runReadOnlyReviewPreflight(');
 const compare=source.indexOf("deny('REVIEW_REQUEST_HEAD_CHANGED')");
 const model=source.indexOf('await executeCompleteLocalSemanticReview(');
 assert.ok(preflight>=0&&compare>preflight&&model>compare);
 assert.match(source,/env\.REVIEWER_B_EXPECTED_HEAD!==preflight\.target\.headSha/);
 assert.match(source,/"REVIEW_REQUEST_HEAD_CHANGED"/);
});
test('long Qwen analysis must refresh the short-lived GitHub App JWT before write',()=>{
 const src=readFileSync(new globalThis.URL('../scripts/protected-real-semantic-review.mjs',
   import.meta.url),'utf8');
 const analysis=src.indexOf('await executeCompleteLocalSemanticReview(');
 const refresh=src.indexOf('const writerNow=Date.now();');
 assert.ok(analysis>0 && refresh>analysis);
 assert.match(src,/const writerJwt=createReviewerBAppJwt\(\{privateKeyPem:pem,now:writerNow\}\)/);
 assert.match(src,/appJwt:writerJwt,purpose:'publish',now:writerNow/);
 assert.doesNotMatch(src,/appJwt:jwt,purpose:'publish',now,fetchImpl/);
});
