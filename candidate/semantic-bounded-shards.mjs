/**
 * Complete bounded semantic review of a GitHub-authenticated PRIVATE diff.
 *
 * Splits each validated hunk into standalone, strictly valid small Git diff
 * fragments, preserving every original change and NEW-side line number.
 * Every fragment must complete real LOCAL inference or the whole run fails.
 * No external model API, report publication or approval authority here.
 */
import {createHash} from 'node:crypto';
import {inspect} from 'node:util';
import {canonicalJson} from '../src/canonical.mjs';
import {deriveAddedLinesFromDiff} from './diff-added-lines.mjs';
import {prepareBoundedSemanticReview} from './semantic-review-request.mjs';
import {executeLocalOllamaReview} from './local-ollama-executor.mjs';

const REPO='deenkids7-dev/deenkids',MODEL='qwen2.5-coder:7b';
const sha=x=>createHash('sha256').update(x).digest('hex');
const HUNK=/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n$/;
function deny(code){throw Error(code);}
function lines(s){return s.match(/[^\n]*\n|[^\n]+$/g)||[];}
function keysEqual(a,b){return JSON.stringify(a)===JSON.stringify(b);}
function snapFor(plan,bytes){
 const s=plan.exactScope;
 return {repository:REPO,repository_id:1282086207,pr_number:s.prNumber,
  head_sha:s.headSha,base_sha:s.baseSha,diff_sha256:sha(bytes)};
}
function makeShard(plan,text,path,sourceIndex){
 const bytes=Buffer.from(text,'utf8');
 if(bytes.length>3072||bytes.length<16)deny('BOUNDED_SHARD_BAD_SIZE');
 const p=prepareBoundedSemanticReview({
   snapshot:snapFor(plan,bytes),rawDiffBytes:bytes
 });
 if(!keysEqual(p.changedPaths,[path]))deny('BOUNDED_SHARD_PATH_CHANGED');
 const item={path,sourceIndex,diffSha256:sha(bytes),
  byteCount:bytes.length,approvalAuthorized:false,
  independentReviewVerified:false};
 Object.defineProperties(item,{
  privateDiffBytes:{enumerable:false,configurable:false,
    get:()=>Buffer.from(bytes)},
  toJSON:{enumerable:false,configurable:false,
    value:()=>({...Object.fromEntries(Object.entries(item)),
      privateDiffBytes:'[REDACTED]'})},
  [inspect.custom]:{enumerable:false,configurable:false,
    value:()=> '[BoundedPrivateSemanticShard: REDACTED; NOT APPROVED]'}
 });
 return Object.freeze(item);
}
/** Pure shape proof. Reject CRLF and unsupported rename/binary/mode-only
 * changes rather than silently skipping any part of the original diff.
 */
export function partitionRealSemanticDiff({plan,maxChunkBytes=1536}={}){
 if(!plan||plan.exactScope?.repository!==REPO||
   !Number.isSafeInteger(plan.exactScope.prNumber)||
   !Number.isSafeInteger(maxChunkBytes)||maxChunkBytes<768||
   maxChunkBytes>3072||!Array.isArray(plan.changedPaths)||
   typeof plan.privateDiffText!=='string')
   deny('SEMANTIC_SHARD_UNTRUSTED_PLAN');
 const original=Buffer.from(plan.privateDiffText,'utf8');
 if(original.length<16||original.length>128*1024||
   sha(original)!==plan.exactScope.diffSha256||
   plan.privateDiffText.includes('\r'))
   deny('SEMANTIC_SHARD_SOURCE_INVALID');
 const anchored=deriveAddedLinesFromDiff({diffBytes:original});
 if(!keysEqual(Object.keys(anchored),plan.changedPaths))
   deny('SEMANTIC_SHARD_SCOPE_MISMATCH');
 const text=plan.privateDiffText;
 const starts=[...text.matchAll(/^diff --git a\/(\S+) b\/(\S+)\n/gm)];
 if(starts.length!==plan.changedPaths.length||starts[0]?.index!==0)
   deny('SEMANTIC_SHARD_FILE_MISMATCH');
 const shards=[];
 let covered=0,coveredLines=0;
 for(let fileIndex=0;fileIndex<starts.length;fileIndex++){
   const start=starts[fileIndex].index;
   const end=starts[fileIndex+1]?.index??text.length;
   const file=text.slice(start,end),path=plan.changedPaths[fileIndex];
   if(starts[fileIndex][1]!==path||starts[fileIndex][2]!==path)
     deny('SEMANTIC_SHARD_FILE_MISMATCH');
   const hunkMarkers=[...file.matchAll(/^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@[^\n]*\n/gm)];
   if(!hunkMarkers.length)deny('SEMANTIC_SHARD_NO_HUNKS');
   const prefix=file.slice(0,hunkMarkers[0].index);
   if(prefix.length>512||!prefix.startsWith('diff --git a/'+path+' b/'+path+'\n'))
     deny('SEMANTIC_SHARD_BAD_HEADER');
   let rebuilt=prefix;
   for(let i=0;i<hunkMarkers.length;i++){
     const marker=hunkMarkers[i],meta=marker[0].match(HUNK);
     if(!meta)deny('SEMANTIC_SHARD_BAD_HUNK');
     const oldStart=Number(meta[1]),oldLen=meta[2]===undefined?1:Number(meta[2]);
     const newStart=Number(meta[3]),newLen=meta[4]===undefined?1:Number(meta[4]);
     const bodyStart=marker.index+marker[0].length;
     const bodyEnd=hunkMarkers[i+1]?.index??file.length;
     const body=file.slice(bodyStart,bodyEnd);
     rebuilt+=marker[0]+body;
     const sourceLines=lines(body);
     const units=[];
     for(const part of sourceLines){
       if(part.startsWith('\\ No newline at end of file')){
         if(!units.length)deny('SEMANTIC_SHARD_ORPHAN_MARKER');
         units[units.length-1]+=part;
       }else if(/^[ +\-]/.test(part)){
         units.push(part);
       }else if(part==='\n'&&sourceLines.at(-1)===part){
         // Git hunk body may have a trailing blank separator; this never
         // contributes source coverage and is not passed to a model.
       }else{
         deny('SEMANTIC_SHARD_BAD_SOURCE_LINE');
       }
     }
     if(!units.length)deny('SEMANTIC_SHARD_EMPTY_HUNK');
     let consumedOld=0,consumedNew=0,chunkLines=[],blockOld=0,blockNew=0;
     const maxData=maxChunkBytes-Buffer.byteLength(prefix,'utf8')-64;
     function flush(){
       if(!chunkLines.length)return;
       const header='@@ -'+(oldStart+consumedOld-blockOld)+','+blockOld+
         ' +'+(newStart+consumedNew-blockNew)+','+blockNew+' @@\n';
       const fragment=prefix+header+chunkLines.join('');
       if(Buffer.byteLength(fragment,'utf8')>maxChunkBytes)
         deny('SEMANTIC_SHARD_CHUNK_TOO_LARGE');
       shards.push(makeShard(plan,fragment,path,fileIndex));
       chunkLines=[];blockOld=0;blockNew=0;
     }
     for(const unit of units){
       const size=Buffer.byteLength(unit,'utf8');
       if(size>maxData)deny('SEMANTIC_SHARD_LINE_TOO_LARGE');
       if(chunkLines.length &&
          Buffer.byteLength(chunkLines.join(''),'utf8')+size>maxData)
          flush();
       chunkLines.push(unit);
       const c=unit[0];
       if(c!=='+' ) {blockOld++;consumedOld++;}
       if(c!=='-' ) {blockNew++;consumedNew++;}
       coveredLines++;
       if(shards.length>96)deny('SEMANTIC_SHARD_TOO_MANY');
     }
     flush();
     if(consumedOld!==oldLen||consumedNew!==newLen)
       deny('SEMANTIC_SHARD_LENGTH_MISMATCH');
   }
   if(rebuilt!==file)deny('SEMANTIC_SHARD_LOSSY_RECONSTRUCTION');
   covered+=Buffer.byteLength(rebuilt,'utf8');
 }
 if(covered!==original.length||!shards.length||shards.length>96||
   coveredLines===0)deny('SEMANTIC_SHARD_LOSSY_RECONSTRUCTION');
 const safe={originalDiffSha256:sha(original),
  originalByteCount:original.length,shardCount:shards.length,
  changedFileCount:starts.length,sourceLineCount:coveredLines,
  rawByteCoverageProven:true,inferenceExecuted:false,
  approvalAuthorized:false,independentReviewVerified:false,
  shards:Object.freeze(shards)};
 Object.defineProperties(safe,{
  toJSON:{enumerable:false,configurable:false,
    value:()=>({...Object.fromEntries(Object.entries(safe)),
      shards:shards.map(x=>x.toJSON())})},
  [inspect.custom]:{enumerable:false,configurable:false,
    value:()=> '[RealSemanticDiffPartitions: PRIVATE BYTES REDACTED]'}
 });
 return Object.freeze(safe);
}
/** Every shard is re-bound to the exact PR and its original private SHA.
 * No incomplete/model-error path yields a result. Global disposition is
 * provisional; model findings are NOT merge authority.
 */
export async function executeCompleteLocalSemanticReview({plan,runId,
  fetchImpl=globalThis.fetch,model=MODEL,maxOutputTokens=1024
}={}){
 if(model!==MODEL||typeof runId!=='string'||typeof fetchImpl!=='function')
   deny('SEMANTIC_BATCH_INPUT_INVALID');
 const parts=partitionRealSemanticDiff({plan});
 const original=Buffer.from(plan.privateDiffText,'utf8');
 if(parts.originalDiffSha256!==sha(original))
   deny('SEMANTIC_BATCH_ORIGINAL_DRIFT');
 const findings=[],responses=[],seen=new Set();
 let modelCalls=0;
 for(const chunk of parts.shards){
   const bytes=chunk.privateDiffBytes;
   const chunkPlan=prepareBoundedSemanticReview({
     snapshot:snapFor(plan,bytes),rawDiffBytes:bytes});
   const result=await executeLocalOllamaReview({
     plan:chunkPlan,trustedDiffBytes:bytes,runId,
     model,approvedLocalPrivateProcessing:true,
     fetchImpl,maxOutputTokens});
   if(result.localModelExecuted!==true||
     result.approvalAuthorized!==false||
     result.independentReviewVerified!==false)
     deny('SEMANTIC_BATCH_LOCAL_NOT_VERIFIED');
   const report=JSON.parse(result.privateCanonicalReportBytes.toString('utf8'));
   if(report.run_id!==runId||!Array.isArray(report.findings)||
     report.findings.length!==result.findingCount)
      deny('SEMANTIC_BATCH_INVALID_REPORT');
   for(const f of report.findings){
     if(seen.has(f.fingerprint))deny('SEMANTIC_BATCH_DUPLICATE_FINDING');
     seen.add(f.fingerprint);
     findings.push(f);
   }
   responses.push(chunk.diffSha256+':'+result.localResponseSha256);
   modelCalls++;
 }
 if(modelCalls!==parts.shardCount)deny('SEMANTIC_BATCH_INCOMPLETE');
 const complete=Buffer.from(canonicalJson({
   schema:'devfactory.reviewer-b.findings.v1',
   run_id:runId,
   summary:'Full immutable PRIVATE diff was processed in '+
     parts.shardCount+' bounded local Qwen parts; model context per part '+
     'is incomplete relative to the full repository, so findings remain provisional.',
   findings
 }),'utf8');
 const result={
   model,localModelExecuted:true,localResponseSha256:sha(responses.join('\n')),
   provisionalState:findings.some(f=>['critical','high'].includes(f.severity))
     ?'FAIL':'INCONCLUSIVE',
   findingCount:findings.length,processedShardCount:modelCalls,
   originalDiffSha256:parts.originalDiffSha256,
   rawByteCoverageProven:true,modelContextCompletenessVerified:false,
   independentReviewVerified:false,approvalAuthorized:false,publishEvent:null
 };
 Object.defineProperties(result,{
  privateCanonicalReportBytes:{enumerable:false,configurable:false,
    get:()=>Buffer.from(complete)},
  toJSON:{enumerable:false,configurable:false,
    value:()=>({...Object.fromEntries(Object.entries(result)),
      privateCanonicalReportBytes:'[REDACTED]'})},
  [inspect.custom]:{enumerable:false,configurable:false,
    value:()=> '[CompleteLocalSemanticReview: PRIVATE REPORT REDACTED; NOT APPROVED]'}
 });
 return Object.freeze(result);
}
