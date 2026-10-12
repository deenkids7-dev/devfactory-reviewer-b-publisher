import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {inspect} from 'node:util';
import {deriveAddedLinesFromDiff} from '../candidate/diff-added-lines.mjs';
import {prepareBoundedSemanticReview} from '../candidate/semantic-review-request.mjs';
import {partitionRealSemanticDiff,planAdaptiveSemanticShards,
 executeCompleteLocalSemanticReview}
 from '../candidate/semantic-bounded-shards.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const HEAD='a'.repeat(40),BASE='b'.repeat(40);
const RUN='gh-38140023698-1';
function file(path,lines=25){
 const body=Array.from({length:lines},(_,i)=>'+changed_'+i+
   '_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n').join('');
 return 'diff --git a/'+path+' b/'+path+'\n'+
  'index 1234567..abcdef0 100644\n--- a/'+path+'\n+++ b/'+path+'\n'+
  '@@ -1,1 +1,'+(lines+1)+' @@\n old_line\n'+body;
}
const paths=['src/alpha.mjs','src/beta.mjs'];
const diff=Buffer.from(paths.map(p=>file(p)).join(''));
function plan(bytes=diff){return prepareBoundedSemanticReview({
 snapshot:{repository:'deenkids7-dev/deenkids',repository_id:1282086207,
  pr_number:899,head_sha:HEAD,base_sha:BASE,diff_sha256:sha(bytes)},
 rawDiffBytes:bytes
});}
function fakeReply(content){
 return {status:200,url:'http://127.0.0.1:11434/api/chat',
  redirected:false,headers:{get:k=>k==='content-type'?'application/json':null},
  body:new Response(JSON.stringify(content)).body};
}
function mockModel({high=false,failAt=-1}={}){
 let calls=0,seen=[];
 const fetchImpl=async(url,options)=>{
   const n=++calls;
   if(n===failAt)throw Error('LOCAL_SYNTHETIC_MODEL_FAILURE');
   assert.equal(url,'http://127.0.0.1:11434/api/chat');
   const request=JSON.parse(options.body);
   assert.equal(request.keep_alive,'5m');
   const input=JSON.parse(request.messages[1].content);
   const bytes=Buffer.from(input.untrusted_unified_diff);
   const anchors=deriveAddedLinesFromDiff({diffBytes:bytes});
   const path=Object.keys(anchors)[0];
   assert.deepEqual(request.format.properties.findings.items.properties.line.enum,
     anchors[path]);
   seen.push({path,line:anchors[path][0],bytes});
   const findings=high&&n===1?[{
     severity:'high',path,line:anchors[path][0],
     message:'Reproducible synthetic regression',
     evidence:'One changed line permits unauthorized input'
   }]:[];
   return fakeReply({
     model:'qwen2.5-coder:7b',done:true,done_reason:'stop',
     message:{role:'assistant',content:JSON.stringify({
       summary:'Synthetic real local inference call '+n,findings})},
     prompt_eval_count:800,eval_count:120
   });
 };
 return {fetchImpl,count:()=>calls,seen};
}
test('every NEW-side line is represented in valid standalone local shards',()=>{
 const p=partitionRealSemanticDiff({plan:plan(),maxChunkBytes:768});
 assert.equal(p.rawByteCoverageProven,true);
 assert.equal(p.originalDiffSha256,sha(diff));
 assert.equal(p.changedFileCount,2);
 assert.ok(p.shardCount>2);
 const inputAnchors=deriveAddedLinesFromDiff({diffBytes:diff});
 const reconstructed={};
 for(const chunk of p.shards){
   assert.ok(chunk.byteCount<=768);
   const anch=deriveAddedLinesFromDiff({diffBytes:chunk.privateDiffBytes});
   const path=Object.keys(anch)[0];
   reconstructed[path]??=[];
   reconstructed[path].push(...anch[path]);
 }
 assert.equal(JSON.stringify(reconstructed),JSON.stringify(inputAnchors));
 assert.equal(p.approvalAuthorized,false);
 assert.equal(p.independentReviewVerified,false);
 assert.doesNotMatch(JSON.stringify(p),/changed_0_xxx/);
 assert.doesNotMatch(inspect(p),/changed_0_xxx/);
});
test('Gemini: long valid nested pathname header is supported without partial coverage',()=>{
 const name='src/'+('subdir/'.repeat(13))+'very-long-valid-module-name.mjs';
 const bytes=Buffer.from(file(name,20));
 const header=bytes.toString('utf8').split('@@ ')[0];
 assert.ok(Buffer.byteLength(header,'utf8')>512);
 assert.ok(Buffer.byteLength(header,'utf8')<1024);
 const result=partitionRealSemanticDiff({plan:plan(bytes)});
 assert.equal(result.changedFileCount,1);
 assert.equal(result.rawByteCoverageProven,true);
 assert.ok(result.shardCount>0);
 const all=[];
 for(const shard of result.shards){
  const anchors=deriveAddedLinesFromDiff({diffBytes:shard.privateDiffBytes});
  all.push(...anchors[name]);
 }
 assert.deepEqual(all,deriveAddedLinesFromDiff({diffBytes:bytes})[name]);
});
test('numeric-only pathname preserves strict authenticated ordered scope',()=>{
 const bytes=Buffer.from(file('src/alpha.mjs',6)+file('123',6));
 const scope=plan(bytes);
 assert.deepEqual(scope.changedPaths,['src/alpha.mjs','123']);
 const found=partitionRealSemanticDiff({plan:scope});
 assert.equal(found.changedFileCount,2);
 assert.deepEqual(found.shards.map(s=>s.path),
  ['src/alpha.mjs','123']);
 assert.equal(found.rawByteCoverageProven,true);
 const forged={...scope,privateDiffText:scope.privateDiffText,
  changedPaths:['123','src/alpha.mjs']};
 assert.throws(()=>partitionRealSemanticDiff({plan:forged}),
  /SEMANTIC_SHARD_FILE_MISMATCH/);
});
test('security: changed-file encounter order is binding and cannot be sorted away',()=>{
 const trusted=plan();
 const reordered={...trusted,
   privateDiffText:trusted.privateDiffText,
   changedPaths:[...trusted.changedPaths].reverse()};
 assert.throws(()=>partitionRealSemanticDiff({plan:reordered}),
   /SEMANTIC_SHARD_FILE_MISMATCH/);
});
test('real semantic model called once per exact bounded shard, then one bound report',async()=>{
 const model=mockModel();
 const p=planAdaptiveSemanticShards({plan:plan()}).partitions;
 const r=await executeCompleteLocalSemanticReview({
   plan:plan(),runId:RUN,fetchImpl:model.fetchImpl});
 assert.equal(model.count(),p.shardCount);
 assert.equal(r.processedShardCount,p.shardCount);
 assert.equal(r.rawByteCoverageProven,true);
 assert.equal(r.originalDiffSha256,sha(diff));
 assert.equal(r.localModelExecuted,true);
 assert.equal(r.provisionalState,'INCONCLUSIVE');
 assert.equal(r.findingCount,0);
 assert.equal(r.approvalAuthorized,false);
 assert.equal(r.independentReviewVerified,false);
 assert.equal(r.publishEvent,null);
 assert.doesNotMatch(JSON.stringify(r),/changed_0_xxx/);
 const report=JSON.parse(r.privateCanonicalReportBytes.toString('utf8'));
 assert.equal(report.run_id,RUN);
 assert.equal(report.findings.length,0);
});
test('real HIGH finding survives complete local shard aggregation, never PASS',async()=>{
 const model=mockModel({high:true});
 const r=await executeCompleteLocalSemanticReview({
   plan:plan(),runId:RUN,fetchImpl:model.fetchImpl});
 assert.equal(r.provisionalState,'FAIL');
 assert.equal(r.findingCount,1);
 const report=JSON.parse(r.privateCanonicalReportBytes.toString('utf8'));
 assert.equal(report.findings[0].severity,'high');
 assert.equal(report.findings[0].path,'src/alpha.mjs');
 assert.equal(r.approvalAuthorized,false);
});
test('one transient LOCAL failure is recovered by complete smaller authenticated fragments',async()=>{
 const model=mockModel({failAt:2});
 const src=plan();
 const original=planAdaptiveSemanticShards({plan:src}).partitions;
 const done=await executeCompleteLocalSemanticReview({
   plan:src,runId:RUN,fetchImpl:model.fetchImpl
 });
 assert.ok(model.count()>original.shardCount);
 assert.ok(done.processedShardCount>original.shardCount);
 assert.equal(done.rawByteCoverageProven,true);
 assert.equal(done.originalDiffSha256,sha(diff));
 assert.equal(done.localModelExecuted,true);
 assert.equal(done.approvalAuthorized,false);
 assert.equal(done.independentReviewVerified,false);
 const received={};
 for(const item of model.seen){
   const loc=deriveAddedLinesFromDiff({diffBytes:item.bytes});
   (received[item.path]??=[]).push(...loc[item.path]);
 }
 assert.equal(JSON.stringify(received),
   JSON.stringify(deriveAddedLinesFromDiff({diffBytes:diff})));
 assert.doesNotMatch(JSON.stringify(done),/changed_0_xxx/);
});
test('one Ollama output-budget exhaustion reanalyzes entire trusted shard in smaller pieces',async()=>{
 const trusted=plan();
 const baseline=planAdaptiveSemanticShards({plan:trusted}).partitions;
 const model=mockModel();
 let requests=0;
 const fetchImpl=async(...args)=>{
   requests++;
   if(requests===2){
     return fakeReply({
       model:'qwen2.5-coder:7b',done:true,done_reason:'length',
       message:{role:'assistant',content:'{"summary":"unfinished"'},
       prompt_eval_count:800,eval_count:1024
     });
   }
   return model.fetchImpl(...args);
 };
 const result=await executeCompleteLocalSemanticReview({
   plan:trusted,runId:RUN,fetchImpl});
 assert.ok(requests>baseline.shardCount);
 assert.ok(result.processedShardCount>baseline.shardCount);
 assert.equal(result.rawByteCoverageProven,true);
 assert.equal(result.originalDiffSha256,sha(diff));
 assert.equal(result.approvalAuthorized,false);
 assert.equal(result.independentReviewVerified,false);
 assert.equal(result.provisionalState,'INCONCLUSIVE');
 const report=JSON.parse(result.privateCanonicalReportBytes.toString('utf8'));
 assert.equal(report.findings.length,0);
});
test('two independent length stops reanalyze every original added line without partial output',async()=>{
 const trusted=plan();
 const model=mockModel();
 const exhausted=new Set();
 let uplift=0,requests=0;
 const fetchImpl=async(url,options)=>{
   requests++;
   const request=JSON.parse(options.body);
   const scoped=JSON.parse(request.messages[1].content);
   const anchors=deriveAddedLinesFromDiff({
     diffBytes:Buffer.from(scoped.untrusted_unified_diff)});
   const path=Object.keys(anchors)[0];
   if(request.options.num_predict===1024&&!exhausted.has(path)){
     exhausted.add(path);
     return fakeReply({
       model:'qwen2.5-coder:7b',done:true,done_reason:'length',
       message:{role:'assistant',content:'{"summary":"truncated"'},
       prompt_eval_count:800,eval_count:1024
     });
   }
   if(request.options.num_predict===2048)uplift++;
   return model.fetchImpl(url,options);
 };
 const result=await executeCompleteLocalSemanticReview({
   plan:trusted,runId:RUN,fetchImpl});
 assert.deepEqual([...exhausted].sort(),[...paths].sort());
 assert.ok(uplift>=2);
 assert.ok(requests<=128);
 assert.equal(result.rawByteCoverageProven,true);
 assert.equal(result.originalDiffSha256,sha(diff));
 assert.equal(result.approvalAuthorized,false);
 assert.equal(result.independentReviewVerified,false);
 const observed={};
 for(const item of model.seen){
   const anchors=deriveAddedLinesFromDiff({diffBytes:item.bytes});
   (observed[item.path]??=[]).push(...anchors[item.path]);
 }
 assert.equal(JSON.stringify(observed),
   JSON.stringify(deriveAddedLinesFromDiff({diffBytes:diff})));
});
test('too-small-to-split length stop gets one larger-output local attempt',async()=>{
 const bytes=Buffer.from(file('src/tiny.mjs',1));
 const trusted=plan(bytes);
 const model=mockModel();
 let requests=0;
 const fetchImpl=async(url,options)=>{
   requests++;
   const tokenCap=JSON.parse(options.body).options.num_predict;
   if(requests===1){
     assert.equal(tokenCap,1024);
     return fakeReply({
       model:'qwen2.5-coder:7b',done:true,done_reason:'length',
       message:{role:'assistant',content:'{"summary":"truncated"'},
       prompt_eval_count:800,eval_count:1024
     });
   }
   assert.equal(tokenCap,2048);
   return model.fetchImpl(url,options);
 };
 const result=await executeCompleteLocalSemanticReview({
   plan:trusted,runId:RUN,fetchImpl});
 assert.equal(requests,2);
 assert.equal(result.rawByteCoverageProven,true);
 assert.equal(result.originalDiffSha256,sha(bytes));
 assert.equal(result.approvalAuthorized,false);
});
test('persistent Qwen length exhaustion remains fail-closed after one bounded budget change',async()=>{
 const bytes=Buffer.from(file('src/tiny.mjs',1));
 let requests=0;
 const fetchImpl=async(url,options)=>{
   requests++;
   const cap=JSON.parse(options.body).options.num_predict;
   return fakeReply({
     model:'qwen2.5-coder:7b',done:true,done_reason:'length',
     message:{role:'assistant',content:'{"summary":"truncated"'},
     prompt_eval_count:800,eval_count:cap
   });
 };
 await assert.rejects(()=>executeCompleteLocalSemanticReview({
   plan:plan(bytes),runId:RUN,fetchImpl
 }),/OLLAMA_OUTPUT_TRUNCATED/);
 assert.equal(requests,2);
});
test('wrong-model length response never triggers fallback or a false review result',async()=>{
 let requests=0;
 const fetchImpl=async()=>{
   requests++;
   return fakeReply({
     model:'qwen2.5-coder:1.5b',done:true,done_reason:'length',
     message:{role:'assistant',content:'{"summary":"unfinished"'},
     prompt_eval_count:800,eval_count:1024
   });
 };
 await assert.rejects(()=>executeCompleteLocalSemanticReview({
   plan:plan(),runId:RUN,fetchImpl
 }),/OLLAMA_COMPLETION_UNVERIFIED/);
 assert.equal(requests,1);
});
test('persistent local failure rejects ALL review output after one bounded split',async()=>{
 const model=mockModel();
 let attempts=0;
 const fetchImpl=async(...args)=>{
   attempts++;
   if(attempts>=2)throw Error('SIMULATED_LOCAL_TRANSPORT_LOSS');
   return model.fetchImpl(...args);
 };
 await assert.rejects(()=>executeCompleteLocalSemanticReview({
   plan:plan(),runId:RUN,fetchImpl
 }),/LOCAL_MODEL_REQUEST_FAILED/);
 assert.ok(attempts>=3);
 assert.ok(attempts<=6,'must not spin indefinitely');
});
test('malformed local response is never retried or accepted as a model PASS',async()=>{
 let requests=0;
 const fetchImpl=async()=>{
   requests++;
   return {status:302,redirected:true,url:'https://example.invalid/',
     headers:{get:()=> 'text/html'},body:null};
 };
 await assert.rejects(()=>executeCompleteLocalSemanticReview({
   plan:plan(),runId:RUN,fetchImpl
 }),/LOCAL_MODEL_ENDPOINT_UNVERIFIED/);
 assert.equal(requests,1);
});
test('invalid diff source, changing digest, CRLF or huge line cannot be silently skipped',()=>{
 const original=plan();
 const wrong={...original,privateDiffText:original.privateDiffText,
   exactScope:{...original.exactScope,diffSha256:'f'.repeat(64)}};
 assert.throws(()=>partitionRealSemanticDiff({plan:wrong}),/SEMANTIC_SHARD_SOURCE_INVALID/);
 const crlf=Buffer.from(file('src/a.mjs',4).replace(/\n/g,'\r\n'));
 assert.throws(()=>partitionRealSemanticDiff({plan:plan(crlf)}),
   /SEMANTIC_SHARD_SOURCE_INVALID/);
 const tooLong=Buffer.from(file('src/a.mjs',1).replace('changed_0_',
   'changed_0_'+'z'.repeat(5000)));
 assert.throws(()=>partitionRealSemanticDiff({plan:plan(tooLong)}),
   /SEMANTIC_SHARD_LINE_TOO_LARGE/);
});

test('QUICK lane reduces local calls without skipping one authenticated added line',async()=>{
 const bytes=Buffer.from(file('src/alpha.mjs',65)+file('src/beta.mjs',65));
 const trusted=plan(bytes);
 const baseline=partitionRealSemanticDiff({plan:trusted,maxChunkBytes:1536});
 const route=planAdaptiveSemanticShards({plan:trusted,maxOutputTokens:1024});
 assert.equal(route.mode,'QUICK',route.reason);
 assert.equal(route.geminiAdvisoryRecommended,false);
 assert.ok(route.partitions.shardCount<baseline.shardCount);
 assert.equal(route.partitions.rawByteCoverageProven,true);
 assert.equal(route.partitions.originalDiffSha256,sha(bytes));
 const original=deriveAddedLinesFromDiff({diffBytes:bytes});
 const seen={};
 for(const chunk of route.partitions.shards){
  assert.ok(chunk.byteCount<=3072);
  const anchors=deriveAddedLinesFromDiff({diffBytes:chunk.privateDiffBytes});
  const name=Object.keys(anchors)[0];
  (seen[name]??=[]).push(...anchors[name]);
 }
 assert.equal(JSON.stringify(seen),JSON.stringify(original));
 const model=mockModel();
 const result=await executeCompleteLocalSemanticReview({
   plan:trusted,runId:RUN,fetchImpl:model.fetchImpl});
 assert.equal(result.reviewMode,'QUICK');
 assert.equal(result.geminiAdvisoryRecommended,false);
 assert.equal(result.processedShardCount,route.partitions.shardCount);
 assert.equal(model.count(),route.partitions.shardCount);
 assert.equal(result.originalDiffSha256,sha(bytes));
 assert.equal(result.rawByteCoverageProven,true);
 assert.equal(result.approvalAuthorized,false);
 assert.equal(result.independentReviewVerified,false);
});
test('sensitive runtime and security paths retain DEEP model coverage, Gemini remains advisory',()=>{
 for(const name of [
  'devfactory/autonomy/scripts/start.ps1',
  'devfactory/autonomy/lib/controllerCorePreLedgerBase.mjs',
  '.github/workflows/ci.yml',
  'src/auth/session.mjs',
  'supabase/migrations/2026.sql',
  'devfactory/lib/merge-executor-core.mjs',
  'payments/checkout.ts'
 ]){
  const p=plan(Buffer.from(file(name,65)));
  const route=planAdaptiveSemanticShards({plan:p});
  const baseline=partitionRealSemanticDiff({plan:p,maxChunkBytes:1536});
  assert.equal(route.mode,'DEEP',name);
  assert.equal(route.reason,'SENSITIVE_CHANGE');
  assert.equal(route.geminiAdvisoryRecommended,true);
  assert.equal(route.partitions.shardCount,baseline.shardCount);
  assert.equal(route.partitions.originalDiffSha256,baseline.originalDiffSha256);
 }
});
test('QUICK never bypasses strict context budget and falls back BEFORE local inference',()=>{
 const bytes=Buffer.from(file('src/alpha.mjs',65)+file('src/beta.mjs',65));
 const trusted=plan(bytes);
 const low=planAdaptiveSemanticShards({plan:trusted,maxOutputTokens:1024});
 const high=planAdaptiveSemanticShards({plan:trusted,maxOutputTokens:4096});
 assert.equal(low.partitions.rawByteCoverageProven,true);
 assert.equal(high.partitions.rawByteCoverageProven,true);
 assert.ok(high.partitions.shardCount>=low.partitions.shardCount);
 assert.equal(high.partitions.originalDiffSha256,low.partitions.originalDiffSha256);
 const invalid={...trusted,privateDiffText:trusted.privateDiffText,
   changedPaths:[...trusted.changedPaths].reverse()};
 assert.throws(()=>planAdaptiveSemanticShards({plan:invalid}),
  /SEMANTIC_SHARD_FILE_MISMATCH/);
});
test('LARGE diffs and too many files keep exhaustive DEEP lane and do not skip Gemini risk',()=>{
 const paths=['src/a.mjs','src/b.mjs','src/c.mjs','src/d.mjs','src/e.mjs'];
 const scope=plan(Buffer.from(paths.map(n=>file(n,24)).join('')));
 const r=planAdaptiveSemanticShards({plan:scope});
 assert.equal(r.mode,'DEEP');
 assert.equal(r.reason,'LARGE_OR_MANY_FILES');
 assert.equal(r.partitions.changedFileCount,5);
 assert.equal(r.partitions.rawByteCoverageProven,true);
});

test('R71 deletion-only late hunk fails at planning before any local model call',async()=>{
 const bytes=Buffer.from(
  'diff --git a/src/alpha.mjs b/src/alpha.mjs\n'+
  'index 1234567..abcdef0 100644\n--- a/src/alpha.mjs\n'+
  '+++ b/src/alpha.mjs\n@@ -1 +1 @@\n-old\n+new\n'+
  '@@ -11 +11,0 @@\n-if (!user.authorized) return false;\n'
 );
 const trusted=plan(bytes);
 let calls=0;
 const fetchImpl=async()=>{calls++;throw Error('UNEXPECTED_NETWORK');};
 assert.throws(()=>planAdaptiveSemanticShards({plan:trusted}),
  /DIFF_DELETION_ONLY_UNANCHORED/);
 await assert.rejects(()=>executeCompleteLocalSemanticReview({
  plan:trusted,runId:RUN,fetchImpl
 }),/DIFF_DELETION_ONLY_UNANCHORED/);
 assert.equal(calls,0);
});
