import test from 'node:test';
import assert from 'node:assert/strict';
import { runSyntheticLocalOllamaBenchmark,safeBenchmarkErrorCode }
  from '../bench/ollama-synthetic-benchmark.mjs';

const ENDPOINT='http://127.0.0.1:11434/api/chat';
function response(url,body,status=200,redirected=false){
 const bytes=Buffer.from(JSON.stringify(body));
 return {status,url,redirected,
  headers:new Headers({'content-type':'application/json'}),
  body:new ReadableStream({start(controller){
   controller.enqueue(new Uint8Array(bytes));controller.close();
  }})
 };
}
function mock(options={}){
 const calls=[];
 const fetchImpl=async (url,config)=>{
  calls.push({url,config});
  if(options.throwNetwork)throw Error('Never echo unsafe networking exceptions');
  const content=JSON.stringify({summary:'Only synthetic input',findings:[]});
  return response(options.url||url,{
   model:options.model||'qwen2.5-coder:7b',
   done:true,done_reason:'stop',
   message:{role:'assistant',content},
   prompt_eval_count:500,eval_count:120
  },options.status||200,options.redirected||false);
 };
 return {fetchImpl,calls};
}
test('free local benchmark runs four FIXED synthetic examples without GitHub or secrets',async()=>{
 const f=mock();
 const result=await runSyntheticLocalOllamaBenchmark({fetchImpl:f.fetchImpl});
 assert.equal(f.calls.length,4);
 assert.equal(result.testsCompleted,4);
 assert.equal(result.seededSemanticBugs,1);
 assert.equal(result.cleanFixtures,2);
 assert.equal(result.modelQualityCertified,false);
 assert.equal(result.syntheticMetricsMeetTargets,false);
 assert.ok(result.cases.every(c=>Array.isArray(c.modelMessages)));
 assert.ok(result.cases.every(c=>c.modelMessages.length===0));
 assert.equal(result.cases[0].provisionalState,'FAIL');
 assert.equal(result.cases[1].provisionalState,'INCONCLUSIVE');
 assert.equal(result.privateSourceReviewed,false);
 assert.equal(result.independentReviewerProvenanceVerified,false);
 assert.equal(result.approvalAuthorized,false);
 for(const call of f.calls){
  assert.equal(call.url,ENDPOINT);
  assert.equal(call.config.method,'POST');
  assert.equal(call.config.redirect,'error');
  assert.equal(call.config.headers.Accept,'application/json');
  assert.doesNotMatch(call.config.body,/PRIVATE KEY|GITHUB_TOKEN|ghp_/);
  const request=JSON.parse(call.config.body);
  assert.equal(request.model,'qwen2.5-coder:7b');
  assert.match(request.messages[1].content,/synthetic\.yml|auth-synthetic\.mjs/);
 }
});
test('no remote endpoints, redirects, wrong model or failed HTTP are accepted',async()=>{
 for(const options of [
  {url:'https://example.com/model'},
  {redirected:true},{status:403},{model:'unknown'}
 ]){
  const f=mock(options);
  await assert.rejects(
   ()=>runSyntheticLocalOllamaBenchmark({fetchImpl:f.fetchImpl}),
   /OLLAMA_BENCHMARK_HTTP_REJECTED|OLLAMA_COMPLETION_UNVERIFIED/
  );
 }
});
test('local model unavailable fails closed without exposing request contents',async()=>{
 const f=mock({throwNetwork:true});
 await assert.rejects(
  ()=>runSyntheticLocalOllamaBenchmark({fetchImpl:f.fetchImpl}),
  e=>e.message==='OLLAMA_BENCHMARK_LOCAL_UNAVAILABLE'
 );
 assert.equal(f.calls.length,1);
});

test('optional small public synthetic model is pinned, not a release approval',async()=>{
 const f=mock({model:'qwen2.5-coder:1.5b'});
 const r=await runSyntheticLocalOllamaBenchmark({
  fetchImpl:f.fetchImpl,model:'qwen2.5-coder:1.5b'
 });
 assert.equal(r.model,'qwen2.5-coder:1.5b');
 assert.equal(r.approvalAuthorized,false);
 assert.equal(r.independentReviewerProvenanceVerified,false);
 assert.equal(f.calls.length,4);
 for(const call of f.calls){
  const req=JSON.parse(call.config.body);
  assert.equal(req.model,'qwen2.5-coder:1.5b');
  assert.equal(req.options.num_predict,512);
 }
});

test('benchmark failures expose only allowlisted codes, never private contents',()=>{
 assert.equal(safeBenchmarkErrorCode(new Error('OLLAMA_COMPLETION_UNVERIFIED')),
  'OLLAMA_COMPLETION_UNVERIFIED');
 assert.equal(safeBenchmarkErrorCode(new Error('Bearer UNTRUSTED_SECRET_VALUE')),
  'UNCLASSIFIED');
 assert.equal(safeBenchmarkErrorCode(new Error('OLLAMA_X secret=123')),
  'UNCLASSIFIED');
});

test('14B synthetic selection stays bounded, identity-pinned and nonauthorizing',async()=>{
 const f=mock({model:'qwen2.5-coder:14b'});
 const x=await runSyntheticLocalOllamaBenchmark({
   fetchImpl:f.fetchImpl,model:'qwen2.5-coder:14b'
 });
 assert.equal(x.model,'qwen2.5-coder:14b');
 assert.equal(x.testsCompleted,4);
 assert.equal(x.approvalAuthorized,false);
 assert.equal(x.modelQualityCertified,false);
 assert.equal(f.calls.length,4);
 for(const call of f.calls){
   assert.equal(JSON.parse(call.config.body).model,'qwen2.5-coder:14b');
 }
});
