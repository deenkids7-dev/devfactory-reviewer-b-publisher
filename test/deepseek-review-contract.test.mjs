import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { prepareBoundedSemanticReview } from '../candidate/semantic-review-request.mjs';
import {
  prepareDeepSeekCandidate, validateDeepSeekCandidateCompletion
} from '../candidate/deepseek-review-contract.mjs';

const privateMarker='SYNTHETIC_PRIVATE_DIFF_NEVER_IN_PUBLIC_LOG';
const diff=Buffer.from('diff --git a/src/check.mjs b/src/check.mjs\n'+
  'index 123..456 100644\n--- a/src/check.mjs\n+++ b/src/check.mjs\n'+
  '@@ -1 +1 @@\n-before()\n+'+privateMarker+'\n');
const digest=value=>createHash('sha256').update(value).digest('hex');
const target={
  repository:'deenkids7-dev/deenkids',repository_id:1282086207,
  pr_number:898,head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),
  diff_sha256:digest(diff)
};
const plan=()=>prepareBoundedSemanticReview({snapshot:target,rawDiffBytes:diff});
const modelResponse=(content,overrides={})=>({
  model:'deepseek-flash',
  choices:[{
    index:0,finish_reason:'stop',
    message:{role:'assistant',content}
  }],
  usage:{prompt_tokens:8000,completion_tokens:1200},
  ...overrides
});
const empty=JSON.stringify({summary:'No findings, synthetic only.',findings:[]});
const blocker=JSON.stringify({summary:'Synthetic blocker.',findings:[{
  severity:'high',
  path:'src/check.mjs',line:1,
  message:'Synthetic finding',evidence:'Synthetic fixture, no real defect'
}]});
function parseResponse(response, more={}) {
  return validateDeepSeekCandidateCompletion({
    response,expectedModel:'deepseek-flash',
    runId:'synthetic-run-898',trustedChangedPaths:['src/check.mjs'],
    observedInputTokenCeiling:10000,observedOutputTokenCeiling:2048,
    ...more
  });
}
test('single-model DeepSeek candidate creates a strict JSON-only request',()=>{
  const r=prepareDeepSeekCandidate({plan:plan(),inputTokenCeiling:10000});
  assert.equal(r.model,'deepseek-flash');
  assert.equal(r.requestAuthorized,false);
  assert.equal(r.approvalAuthorized,false);
  assert.equal(r.indicativePeakCostUsd,0.0054576);
  assert.equal(r.actualTokenizerVerified,false);
  const body=JSON.parse(r.privateRequestJson);
  assert.equal(body.model,'deepseek-flash');
  assert.equal(body.stream,false);
  assert.equal(body.thinking.type,'disabled');
  assert.equal(body.response_format.type,'json_object');
  assert.equal(body.max_tokens,2048);
  assert.equal(body.messages.length,2);
  assert.equal(body.messages[0].role,'system');
  assert.match(body.messages[1].content,/SYNTHETIC_PRIVATE_DIFF/);
  assert.equal(Object.isFrozen(r),true);
});
test('private diff is nonenumerable and redacted in JSON, spread and inspect',()=>{
  const r=prepareDeepSeekCandidate({plan:plan(),inputTokenCeiling:10000});
  const j=JSON.stringify(r);
  assert.doesNotMatch(j,/SYNTHETIC_PRIVATE_DIFF/);
  assert.doesNotMatch(JSON.stringify({...r}),/SYNTHETIC_PRIVATE_DIFF/);
  assert.doesNotMatch(inspect(r),/SYNTHETIC_PRIVATE_DIFF/);
  assert.match(j,/\[REDACTED\]/);
  assert.ok(!Object.keys(r).includes('privateRequestJson'));
});
test('supports explicitly chosen Pro WITHOUT silent fallback or approval',()=>{
  const r=prepareDeepSeekCandidate({
    plan:plan(),model:'deepseek-v4-pro',
    inputTokenCeiling:10000,maxOutputTokens:2048
  });
  assert.equal(JSON.parse(r.privateRequestJson).model,'deepseek-v4-pro');
  assert.equal(r.approvalAuthorized,false);
});
test('rejects stale and unsupported model IDs',()=>{
  for(const model of ['deepseek-chat','deepseek-reasoner','unknown','']){
    assert.throws(()=>prepareDeepSeekCandidate({
      plan:plan(),inputTokenCeiling:10000,model
    }), e=>e.message==='MODEL_REQUEST_BUDGET_INVALID');
  }
});
test('conservative indicative cost limit blocks expensive requests',()=>{
  assert.throws(()=>prepareDeepSeekCandidate({
    plan:plan(),inputTokenCeiling:200000,
    model:'deepseek-v4-pro',maxOutputTokens:4096
  }),e=>e.message==='MODEL_INDICATIVE_COST_EXCEEDED');
});
test('rejects invalid budget inputs',()=>{
  for(const value of [0,-1,1.5,Infinity,200001]){
    assert.throws(()=>prepareDeepSeekCandidate({
      plan:plan(),inputTokenCeiling:value
    }),e=>e.message==='MODEL_REQUEST_BUDGET_INVALID');
  }
});
test('rejects forged PR target and source bytes',()=>{
  const a=plan();
  const forged={...a,exactScope:{...a.exactScope,repository:'evil/repo'}};
  assert.throws(()=>prepareDeepSeekCandidate({
    plan:forged,inputTokenCeiling:10000
  }),e=>e.message==='MODEL_REQUEST_SCOPE_INVALID');
});
test('clean completion stays INCONCLUSIVE and never authorizes approval',()=>{
  const r=parseResponse(modelResponse(empty));
  assert.equal(r.provisionalState,'INCONCLUSIVE');
  assert.equal(r.reviewerIndependenceVerified,false);
  assert.equal(r.approvalAuthorized,false);
  assert.equal(r.publishEvent,null);
  assert.equal(r.reportedInputTokens,8000);
});
test('model blocking finding returns provisional FAIL only',()=>{
  const r=parseResponse(modelResponse(blocker));
  assert.equal(r.provisionalState,'FAIL');
  assert.equal(r.findingCount,1);
  assert.equal(r.approvalAuthorized,false);
});
test('truncated completion is refused',()=>{
  assert.throws(()=>parseResponse(modelResponse(empty,{
    choices:[{index:0,finish_reason:'length',
      message:{role:'assistant',content:empty}}]
  })),e=>e.message==='MODEL_COMPLETION_INCOMPLETE_OR_UNTRUSTED');
});
test('provider error, missing usage or wrong model fails closed',()=>{
  for(const r of [
    {error:{message:'not authorized'}},
    modelResponse(empty,{usage:null}),
    modelResponse(empty,{model:'deepseek-v4-pro'}),
    modelResponse(empty,{choices:[]}),
    modelResponse(empty,{choices:[
      {index:0,finish_reason:'content_filter',message:{role:'assistant',content:empty}}
    ]})
  ]){
    assert.throws(()=>parseResponse(r),e=>e.message==='MODEL_COMPLETION_INCOMPLETE_OR_UNTRUSTED');
  }
});
test('model-supplied PASS or unauthorized file path fails closed',()=>{
  const withPass=JSON.stringify({
    summary:'looks good',findings:[],approvalAuthorized:true
  });
  const wrongPath=JSON.stringify({
    summary:'wrong file',findings:[{
      severity:'high',path:'secret/file.mjs',
      line:1,message:'fake',evidence:'out of scope'
    }]
  });
  assert.throws(()=>parseResponse(modelResponse(withPass)),/MODEL_FINDING_SCHEMA_INVALID/);
  assert.throws(()=>parseResponse(modelResponse(wrongPath)),/REVIEW_FINDING_INVALID/);
});

test('declared usage caps and indicative spending ceiling are enforced',()=>{
  for(const usage of [
    {prompt_tokens:10001,completion_tokens:1200},
    {prompt_tokens:8000,completion_tokens:2049}
  ]){
    assert.throws(()=>parseResponse(modelResponse(empty,{usage})),
      e=>e.message==='MODEL_COMPLETION_BUDGET_EXCEEDED');
  }
  assert.throws(()=>parseResponse(modelResponse(empty),{
    maxObservedPeakUsd:0.0001
  }),e=>e.message==='MODEL_COMPLETION_BUDGET_EXCEEDED');
});
test('no trusted tokenizer ceiling means STOP, even for a green model output',()=>{
  assert.throws(()=>parseResponse(modelResponse(empty),{
    observedInputTokenCeiling:undefined
  }),e=>e.message==='MODEL_USAGE_BUDGET_CONTEXT_MISSING');
});

test('model must not supply its own fingerprint or source identity',()=>{
  const fake=JSON.stringify({summary:'Claimed',findings:[{
    fingerprint:'0'.repeat(64),severity:'high',
    path:'src/check.mjs',line:1,message:'fake',evidence:'untrusted'
  }]});
  assert.throws(()=>parseResponse(modelResponse(fake)),
    e=>e.message==='MODEL_FINDING_SCHEMA_INVALID');
});
test('malformed model findings cannot bypass deterministic fingerprints',()=>{
  const fake=JSON.stringify({summary:'Claimed',findings:[{
    severity:'high',path:'src/check.mjs',line:1,
    message:'fake',evidence:'untrusted',approvalAuthorized:true
  }]});
  assert.throws(()=>parseResponse(modelResponse(fake)),
    e=>e.message==='MODEL_FINDING_SCHEMA_INVALID');
});

test('validated model report can flow privately into the signed evidence pipeline',()=>{
  const completion=parseResponse(modelResponse(blocker));
  const bytes=completion.privateCanonicalReportBytes;
  assert.ok(Buffer.isBuffer(bytes));
  const report=JSON.parse(bytes.toString('utf8'));
  assert.equal(report.schema,'devfactory.reviewer-b.findings.v1');
  assert.equal(report.run_id,'synthetic-run-898');
  assert.equal(report.findings.length,1);
  assert.match(report.findings[0].fingerprint,/^[0-9a-f]{64}$/);
  assert.equal(completion.approvalAuthorized,false);
  assert.equal(completion.publishEvent,null);
});
test('private model findings stay out of logs, copies and JSON serialization',()=>{
  const sensitive='SYNTHETIC_PRIVATE_FINDING_NEVER_IN_LOGS';
  const payload=JSON.stringify({summary:'synthetic',findings:[{
    severity:'high',path:'src/check.mjs',line:1,
    message:sensitive,evidence:'synthetic-only evidence'
  }]});
  const r=parseResponse(modelResponse(payload));
  assert.ok(r.privateCanonicalReportBytes.toString().includes(sensitive));
  assert.doesNotMatch(JSON.stringify(r),/SYNTHETIC_PRIVATE_FINDING/);
  assert.doesNotMatch(JSON.stringify({...r}),/SYNTHETIC_PRIVATE_FINDING/);
  assert.doesNotMatch(inspect(r),/SYNTHETIC_PRIVATE_FINDING/);
  assert.match(JSON.stringify(r),/\[REDACTED\]/);
  assert.ok(!Object.keys(r).includes('privateCanonicalReportBytes'));
  const exposed=r.privateCanonicalReportBytes;
  exposed.fill(0);
  assert.ok(r.privateCanonicalReportBytes.toString().includes(sensitive),
    'caller cannot mutate privately held canonical report by altering a copy');
});

test('model formatting whitespace normalizes before stable fingerprint generation',()=>{
 const formatted=JSON.stringify({summary:'Synthetic\n  summary \t safely',findings:[{
   severity:'high',path:'src/check.mjs',line:1,
   message:'  Missing\n validation \t of input  ',
   evidence:'Before:\r\n unchecked\tvalue  '
 }]});
 const completion=parseResponse(modelResponse(formatted));
 assert.equal(completion.provisionalState,'FAIL');
 const report=JSON.parse(completion.privateCanonicalReportBytes.toString('utf8'));
 assert.equal(report.summary,'Synthetic summary safely');
 assert.equal(report.findings[0].message,'Missing validation of input');
 assert.equal(report.findings[0].evidence,'Before: unchecked value');
 const fp=report.findings[0].fingerprint;
 assert.match(fp,/^[a-f0-9]{64}$/);
 assert.equal(parseResponse(modelResponse(formatted)).privateCanonicalReportBytes.toString(),
   completion.privateCanonicalReportBytes.toString());
 assert.equal(completion.approvalAuthorized,false);
});
test('unsupported model control characters still fail closed',()=>{
 const bad=JSON.stringify({summary:'safe',findings:[{
  severity:'high',path:'src/check.mjs',line:1,
  message:'contains\u0000unexpected control',
  evidence:'Synthetic reason'
 }]});
 assert.throws(()=>parseResponse(modelResponse(bad)),/REVIEW_FINDING_INVALID|UNSUPPORTED_CANONICAL_VALUE/);
});
