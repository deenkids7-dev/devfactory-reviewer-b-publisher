import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { deriveAddedLinesFromDiff } from './diff-added-lines.mjs';

// Pure prospective SHARD PREPARATION ONLY: not an inference orchestrator,
// scheduler, provenance witness, signature or approval gate.
// Every entire file/hunk must fit. Oversized single files fail CLOSED.
const SHA256=/^[a-f0-9]{64}$/;
const PATH=/^(?!\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;
function deny(code){throw Error(code);}
function digest(data){return createHash('sha256').update(data).digest('hex');}
function safeChunk(bytes,paths){
  const data=Buffer.from(bytes);
  const value={
    chunkSha256:digest(data),
    byteCount:data.length,
    changedPaths:Object.freeze([...paths]),
    independentReviewVerified:false,approvalAuthorized:false
  };
  Object.defineProperties(value,{
    privateDiffBytes:{
      enumerable:false,configurable:false,get:()=>Buffer.from(data)
    },
    toJSON:{
      enumerable:false,configurable:false,value:()=>({
        chunkSha256:value.chunkSha256,byteCount:value.byteCount,
        changedPaths:value.changedPaths,privateDiffBytes:'[REDACTED]',
        independentReviewVerified:false,approvalAuthorized:false
      })
    },
    [inspect.custom]:{
      enumerable:false,configurable:false,
      value:()=> '[BoundedDiffShard: PRIVATE CONTENT REDACTED; NOT REVIEWED]'
    }
  });
  return Object.freeze(value);
}
/**
 * Partition a whole authenticated Git diff into file-aligned bounded shards.
 * A future witness must attest to the ORIGINAL whole-diff SHA and all shards.
 * This helper cannot prove the GitHub response was authenticated or reviewed.
 */
export function partitionBoundedGitDiff({
  rawDiffBytes,trustedDiffSha256,trustedChangedPaths,
  maxChunkBytes=3072
}={}){
  if(!Buffer.isBuffer(rawDiffBytes)||rawDiffBytes.length<16||
    rawDiffBytes.length>2*1024*1024||
    !SHA256.test(trustedDiffSha256)||digest(rawDiffBytes)!==trustedDiffSha256||
    !Array.isArray(trustedChangedPaths)||trustedChangedPaths.length<1||
    trustedChangedPaths.length>100||
    new Set(trustedChangedPaths).size!==trustedChangedPaths.length||
    trustedChangedPaths.some(p=>typeof p!=='string'||!PATH.test(p))||
    !Number.isSafeInteger(maxChunkBytes)||maxChunkBytes<512||
    maxChunkBytes>8192)deny('REVIEW_SHARDS_SCOPE_UNVERIFIED');

  const text=rawDiffBytes.toString('utf8');
  if(!Buffer.from(text,'utf8').equals(rawDiffBytes)||text.includes('\0')||
    /^(?:Binary files |GIT binary patch)/m.test(text))
    deny('REVIEW_SHARDS_ENCODING_UNSUPPORTED');
  const boundaries=[...text.matchAll(/^diff --git a\/(\S+) b\/(\S+)$/gm)];
  if(boundaries.length!==trustedChangedPaths.length||
    boundaries[0]?.index!==0)deny('REVIEW_SHARDS_FILE_COVERAGE_INVALID');
  const shards=[],whole=[],currentPaths=[];
  let currentBytes=0;
  function flush(){
    if(!whole.length)return;
    const data=Buffer.concat(whole,currentBytes);
    shards.push(safeChunk(data,currentPaths));
    whole.length=0;currentPaths.length=0;currentBytes=0;
  }
  for(let i=0;i<boundaries.length;i++){
    const match=boundaries[i],path=match[1];
    if(path!==trustedChangedPaths[i]||path!==match[2])
      deny('REVIEW_SHARDS_FILE_COVERAGE_INVALID');
    const end=i+1<boundaries.length?boundaries[i+1].index:text.length;
    const bytes=Buffer.from(text.slice(match.index,end),'utf8');
    if(bytes.length>maxChunkBytes)deny('REVIEW_SHARDS_SINGLE_FILE_OVERSIZED');
    // Strict hunk parser must recognize exactly this complete changed file.
    const anchors=deriveAddedLinesFromDiff({diffBytes:bytes});
    if(Object.keys(anchors).length!==1||!Object.hasOwn(anchors,path))
      deny('REVIEW_SHARDS_FILE_COVERAGE_INVALID');
    if(currentBytes+bytes.length>maxChunkBytes)flush();
    whole.push(bytes);currentPaths.push(path);
    currentBytes+=bytes.length;
  }
  flush();
  if(shards.length<1||shards.length>100||
    shards.flatMap(s=>s.changedPaths).join('\0')!==
      trustedChangedPaths.join('\0'))deny('REVIEW_SHARDS_FILE_COVERAGE_INVALID');
  const rebuilt=Buffer.concat(shards.map(s=>s.privateDiffBytes));
  if(!rebuilt.equals(rawDiffBytes)||digest(rebuilt)!==trustedDiffSha256)
    deny('REVIEW_SHARDS_RECONSTRUCTION_FAILED');
  const result={
    wholeDiffSha256:trustedDiffSha256,
    changedFileCount:trustedChangedPaths.length,
    chunkCount:shards.length,
    chunks:Object.freeze(shards),
    coverageComplete:true,
    inferenceExecuted:false,
    independentReviewVerified:false,
    approvalAuthorized:false,
    publishEvent:null
  };
  Object.defineProperties(result,{
    toJSON:{enumerable:false,configurable:false,
      value:()=>({
        wholeDiffSha256:result.wholeDiffSha256,
        changedFileCount:result.changedFileCount,chunkCount:result.chunkCount,
        chunks:result.chunks.map(x=>x.toJSON()),
        coverageComplete:true,inferenceExecuted:false,
        independentReviewVerified:false,approvalAuthorized:false,
        publishEvent:null
      })},
    [inspect.custom]:{enumerable:false,configurable:false,
      value:()=> '[BoundedGitDiffPartition: PRIVATE DIFF REDACTED; NO REVIEW PERFORMED]'}
  });
  return Object.freeze(result);
}

/**
 * An alternative, lossless TEXT SPAN partition for files larger than a
 * context-sized shard. Spans are NOT standalone Git diffs and may begin
 * mid-hunk: no semantic model call or approval may consume them directly.
 */
function safeTextSpan(bytes,path,fileNumber,byteStart,lineStart,lineEndExclusive){
  const data=Buffer.from(bytes);
  const result={
    path,fileNumber,byteStart,byteEndExclusive:byteStart+data.length,
    lineStart,lineEndExclusive,
    spanSha256:digest(data),byteCount:data.length,
    inferenceExecuted:false,approvalAuthorized:false
  };
  Object.defineProperties(result,{
    privateSliceBytes:{enumerable:false,configurable:false,
      get:()=>Buffer.from(data)},
    toJSON:{enumerable:false,configurable:false,
      value:()=>({...Object.fromEntries(Object.entries(result)),
        privateSliceBytes:'[REDACTED]'})},
    [inspect.custom]:{enumerable:false,configurable:false,
      value:()=> '[LosslessGitDiffSpan: PRIVATE BYTES REDACTED; NOT A REVIEW]'}
  });
  return Object.freeze(result);
}
export function partitionLosslessDiffLines({
  rawDiffBytes,trustedDiffSha256,trustedChangedPaths,
  maxSpanBytes=3072
}={}){
  if(!Buffer.isBuffer(rawDiffBytes)||rawDiffBytes.length<16||
    rawDiffBytes.length>2*1024*1024||
    !SHA256.test(trustedDiffSha256)||
    digest(rawDiffBytes)!==trustedDiffSha256||
    !Array.isArray(trustedChangedPaths)||trustedChangedPaths.length<1||
    trustedChangedPaths.length>100||
    new Set(trustedChangedPaths).size!==trustedChangedPaths.length||
    trustedChangedPaths.some(p=>typeof p!=='string'||!PATH.test(p))||
    !Number.isSafeInteger(maxSpanBytes)||maxSpanBytes<512||
    maxSpanBytes>8192)
    deny('REVIEW_SPANS_SCOPE_UNVERIFIED');
  const text=rawDiffBytes.toString('utf8');
  if(!Buffer.from(text,'utf8').equals(rawDiffBytes)||text.includes('\0')||
    /^(?:Binary files |GIT binary patch)/m.test(text))
    deny('REVIEW_SPANS_ENCODING_UNSUPPORTED');
  const boundaries=[...text.matchAll(/^diff --git a\/(\S+) b\/(\S+)$/gm)];
  if(boundaries.length!==trustedChangedPaths.length||
     boundaries[0]?.index!==0)
    deny('REVIEW_SPANS_FILE_COVERAGE_INVALID');
  const spans=[];let absoluteByte=0,absoluteLine=1;
  for(let fileIndex=0;fileIndex<boundaries.length;fileIndex++){
    const m=boundaries[fileIndex],path=m[1];
    if(path!==trustedChangedPaths[fileIndex]||m[2]!==path)
      deny('REVIEW_SPANS_FILE_COVERAGE_INVALID');
    const end=boundaries[fileIndex+1]?.index??text.length;
    const wholeFile=Buffer.from(text.slice(m.index,end),'utf8');
    const anchors=deriveAddedLinesFromDiff({diffBytes:wholeFile});
    if(Object.keys(anchors).length!==1||!Object.hasOwn(anchors,path))
      deny('REVIEW_SPANS_FILE_COVERAGE_INVALID');
    const lines=text.slice(m.index,end).match(/[^\n]*\n|[^\n]+$/g)||[];
    let parts=[],partSize=0,startByte=absoluteByte,startLine=absoluteLine;
    function flush(){
      if(!parts.length)return;
      spans.push(safeTextSpan(Buffer.concat(parts,partSize),path,
        fileIndex,startByte,startLine,absoluteLine));
      parts=[];partSize=0;
      startByte=absoluteByte;startLine=absoluteLine;
    }
    for(const line of lines){
      const bytes=Buffer.from(line,'utf8');
      if(bytes.length>maxSpanBytes)
        deny('REVIEW_SPANS_SINGLE_LINE_OVERSIZED');
      if(partSize+bytes.length>maxSpanBytes)flush();
      if(!parts.length){startByte=absoluteByte;startLine=absoluteLine;}
      parts.push(bytes);partSize+=bytes.length;
      absoluteByte+=bytes.length;absoluteLine++;
      if(spans.length>1024)deny('REVIEW_SPANS_TOO_MANY');
    }
    flush();
  }
  if(!spans.length||spans.length>1024||absoluteByte!==rawDiffBytes.length)
    deny('REVIEW_SPANS_RECONSTRUCTION_FAILED');
  for(let i=0;i<spans.length;i++){
    if(spans[i].byteStart!==(i?spans[i-1].byteEndExclusive:0)||
      spans[i].byteEndExclusive>rawDiffBytes.length)
      deny('REVIEW_SPANS_RECONSTRUCTION_FAILED');
  }
  const reconstructed=Buffer.concat(spans.map(s=>s.privateSliceBytes));
  if(!reconstructed.equals(rawDiffBytes)||
    digest(reconstructed)!==trustedDiffSha256)
    deny('REVIEW_SPANS_RECONSTRUCTION_FAILED');
  const result={
    wholeDiffSha256:trustedDiffSha256,
    changedFileCount:trustedChangedPaths.length,
    spanCount:spans.length,
    spans:Object.freeze(spans),
    byteCoverageComplete:true,
    semanticReviewCoverageVerified:false,
    inferenceExecuted:false,
    independentReviewVerified:false,
    approvalAuthorized:false,publishEvent:null
  };
  Object.defineProperties(result,{
    toJSON:{enumerable:false,configurable:false,
      value:()=>({...Object.fromEntries(Object.entries(result)),
        spans:result.spans.map(x=>x.toJSON())})},
    [inspect.custom]:{enumerable:false,configurable:false,
      value:()=> '[LosslessGitDiffSpans: PRIVATE CONTENT REDACTED; NO REVIEW]'}
  });
  return Object.freeze(result);
}
