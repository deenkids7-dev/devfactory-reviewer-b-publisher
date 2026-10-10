import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { prepareBoundedSemanticReview } from '../candidate/semantic-review-request.mjs';
import { prepareOfflineOllamaCandidate,validateOfflineOllamaCompletion }
  from '../candidate/ollama-offline-contract.mjs';

const sensitive='SYNTHETIC_ONLY_PRIVATE_DIFF_EXAMPLE';
const diff=Buffer.from('diff --git a/src/check.mjs b/src/check.mjs\n'+
 'index 1234567..abcdef0 100644\n--- a/src/check.mjs\n'+
 '+++ b/src/check.mjs\n@@ -1 +1 @@\n-before()\n+'+sensitive+'\n');
const plan=()=>prepareBoundedSemanticReview({
 snapshot:{repository:'deenkids7-dev/deenkids',repository_id:1282086207,
 pr_number:898,head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),
 diff_sha256:createHash('sha256').update(diff).digest('hex')},rawDiffBytes:diff
});
const completion=(content,overrides={})=>({
 model:'qwen2.5-coder:7b',done:true,done_reason:'stop',
 message:{role:'assistant',content},prompt_eval_count:200,eval_count:120,
 ...overrides
});
const noIssues=JSON.stringify({summary:'Synthetic clean example',findings:[]});
const finding=JSON.stringify({summary:'Synthetic blocker',findings:[{
 severity:'high',path:'src/check.mjs',line:1,message:'Artificial defect',
 evidence:'Synthetic evidence'}]});
const parse=(resp,more={})=>validateOfflineOllamaCompletion({
 response:resp,expectedModel:'qwen2.5-coder:7b',
 runId:'synthetic-ollama-898',trustedChangedPaths:['src/check.mjs'],...more
});
test('build local Ollama JSON request, never authorize or publish',()=>{
 const result=prepareOfflineOllamaCandidate({plan:plan()});
 const input=JSON.parse(result.privateRequestJson);
 assert.equal(input.model,'qwen2.5-coder:7b');
 assert.equal(input.stream,false);
 assert.equal(input.format.type,'object');
 assert.equal(input.format.additionalProperties,false);
 assert.deepEqual(input.format.required,['summary','findings']);
 assert.equal(input.format.properties.findings.items.additionalProperties,false);
 assert.equal(input.options.num_ctx,8192);
 assert.equal(input.options.temperature,0);
 assert.equal(input.options.num_predict,2048);
 assert.equal(input.messages.length,2);
 assert.match(input.messages[1].content,/SYNTHETIC_ONLY_PRIVATE/);
 assert.equal(result.approvalAuthorized,false);
 assert.equal(result.independentReviewVerified,false);
 assert.equal(result.modelExecuted,false);
 assert.equal(result.publishEvent,null);
});
test('private prompt stays hidden from JSON, object spread and inspect',()=>{
 const v=prepareOfflineOllamaCandidate({plan:plan()});
 assert.doesNotMatch(JSON.stringify(v),/SYNTHETIC_ONLY_PRIVATE/);
 assert.doesNotMatch(JSON.stringify({...v}),/SYNTHETIC_ONLY_PRIVATE/);
 assert.doesNotMatch(inspect(v),/SYNTHETIC_ONLY_PRIVATE/);
 assert.match(JSON.stringify(v),/REDACTED/);
 assert.ok(!Object.keys(v).includes('privateRequestJson'));
});
test('unknown, cloud, or silently swapped models fail closed',()=>{
 for(const model of ['deepseek-flash','ollama/remote','', 'cloud']){
  assert.throws(()=>prepareOfflineOllamaCandidate({plan:plan(),model}),
    /OLLAMA_MODEL_OR_CONTEXT_UNSUPPORTED/);
 }
});
test('private source SHA must match trusted scope',()=>{
 const p=plan();
 const altered={...p,privateDiffText:p.privateDiffText+'untrusted'};
 assert.throws(()=>prepareOfflineOllamaCandidate({plan:altered}),
   /OLLAMA_SCOPE_UNVERIFIED/);
});
test('clean local output stays INCONCLUSIVE and cannot grant PASS',()=>{
 const v=parse(completion(noIssues));
 assert.equal(v.provisionalState,'INCONCLUSIVE');
 assert.equal(v.approvalAuthorized,false);
 assert.equal(v.independentReviewVerified,false);
 assert.equal(v.publishEvent,null);
});
test('model finding yields provisional FAIL and trusted fingerprint',()=>{
 const v=parse(completion(finding));
 assert.equal(v.provisionalState,'FAIL');
 const report=JSON.parse(v.privateCanonicalReportBytes);
 assert.match(report.findings[0].fingerprint,/^[0-9a-f]{64}$/);
 assert.equal(v.approvalAuthorized,false);
});
test('fake model PASS, fingerprint, or other path rejected',()=>{
 const pass=JSON.stringify({summary:'PASS',findings:[],approvalAuthorized:true});
 const fake=JSON.stringify({summary:'bad',findings:[{
   severity:'high',path:'src/check.mjs',line:1,
   message:'bad',evidence:'fake',fingerprint:'0'.repeat(64)}]});
 const path=JSON.stringify({summary:'bad',findings:[{
   severity:'high',path:'other/secret',line:1,
   message:'bad',evidence:'fake'}]});
 assert.throws(()=>parse(completion(pass)),/OLLAMA_FINDINGS_SCHEMA_INVALID/);
 assert.throws(()=>parse(completion(fake)),/OLLAMA_FINDINGS_SCHEMA_INVALID/);
 assert.throws(()=>parse(completion(path)),/REVIEW_FINDING_INVALID/);
});
test('incomplete, incorrect-model, oversized or invalid outputs blocked',()=>{
 for(const value of [
   completion(noIssues,{done:false}),
   completion(noIssues,{done_reason:'length'}),
   completion(noIssues,{model:'other'}),
   completion(noIssues,{prompt_eval_count:0}),
   completion('{'),
   completion(noIssues,{eval_count:5000}),
   completion(noIssues,{message:{role:'assistant',content:noIssues,tool_calls:[]}})
 ]) assert.throws(()=>parse(value));
});
test('context bounds prevent unexpected inference costs and truncation',()=>{
 assert.throws(()=>parse(completion(noIssues,{prompt_eval_count:550}),
   {maxPromptTokens:500}),/OLLAMA_CONTEXT_LIMIT_EXCEEDED/);
 assert.throws(()=>parse(completion(noIssues,{eval_count:700}),
   {maxCompletionTokens:512}),/OLLAMA_CONTEXT_LIMIT_EXCEEDED/);
});
test('private findings not leaked through safe result serialization',()=>{
 const secret='SYNTHETIC_ONLY_PRIVATE_FINDING';
 const v=parse(completion(JSON.stringify({summary:'fixture',findings:[{
  severity:'high',path:'src/check.mjs',line:1,
  message:secret,evidence:'fixture'
 }]})));
 assert.ok(v.privateCanonicalReportBytes.toString().includes(secret));
 assert.doesNotMatch(JSON.stringify(v),/SYNTHETIC_ONLY_PRIVATE_FINDING/);
 assert.doesNotMatch(JSON.stringify({...v}),/SYNTHETIC_ONLY_PRIVATE_FINDING/);
 assert.doesNotMatch(inspect(v),/SYNTHETIC_ONLY_PRIVATE_FINDING/);
});
