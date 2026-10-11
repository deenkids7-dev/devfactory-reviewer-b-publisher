import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {inspect} from 'node:util';
import {deriveAddedLinesFromDiff} from '../candidate/diff-added-lines.mjs';
import {prepareBoundedSemanticReview} from '../candidate/semantic-review-request.mjs';
import {partitionRealSemanticDiff,executeCompleteLocalSemanticReview}
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
   const input=JSON.parse(request.messages[1].content);
   const bytes=Buffer.from(input.untrusted_unified_diff);
   const anchors=deriveAddedLinesFromDiff({diffBytes:bytes});
   const path=Object.keys(anchors)[0];
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
test('real semantic model called once per exact bounded shard, then one bound report',async()=>{
 const model=mockModel();
 const p=partitionRealSemanticDiff({plan:plan()});
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
test('one incomplete LOCAL model call rejects full review instead of partial acceptance',async()=>{
 const model=mockModel({failAt:2});
 await assert.rejects(()=>executeCompleteLocalSemanticReview({
   plan:plan(),runId:RUN,fetchImpl:model.fetchImpl
 }),/LOCAL_MODEL_REQUEST_FAILED/);
 assert.equal(model.count(),2);
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
