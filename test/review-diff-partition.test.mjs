import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { partitionBoundedGitDiff,partitionLosslessDiffLines } from '../candidate/review-diff-partition.mjs';

const hash=v=>createHash('sha256').update(v).digest('hex');
function file(path,before='old()',after='new()'){
 return 'diff --git a/'+path+' b/'+path+'\n'+
  'index 1234567..abcdef0 100644\n--- a/'+path+'\n'+
  '+++ b/'+path+'\n@@ -1 +1 @@\n-'+before+'\n+'+after+'\n';
}
const paths=['src/one.mjs','src/two.mjs','src/three.mjs'];
const diff=Buffer.from(paths.map((p,i)=>file(p,'old'+i,'new'+i)).join(''));
const run=(bytes=diff,changedPaths=paths,opts={})=>partitionBoundedGitDiff({
 rawDiffBytes:bytes,trustedDiffSha256:hash(bytes),
 trustedChangedPaths:changedPaths,...opts
});
test('fully recover every byte and every ordered changed path from bounded file shards',()=>{
 const p=run(diff,paths,{maxChunkBytes:512});
 assert.equal(p.coverageComplete,true);
 assert.equal(p.changedFileCount,3);
 assert.ok(p.chunkCount>=1);
 assert.equal(p.wholeDiffSha256,hash(diff));
 assert.deepEqual(p.chunks.flatMap(x=>x.changedPaths),paths);
 assert.ok(p.chunks.every(x=>x.byteCount<=512));
 assert.ok(Buffer.concat(p.chunks.map(x=>x.privateDiffBytes)).equals(diff));
 assert.equal(p.approvalAuthorized,false);
 assert.equal(p.independentReviewVerified,false);
 assert.equal(p.inferenceExecuted,false);
});
test('fragment bytes are private from logs and spread JSON/inspection',()=>{
 const secret='SYNTHETIC_ONLY_SOURCE_NEVER_REAL';
 const bytes=Buffer.from(file('src/one.mjs','before()',secret));
 const p=run(bytes,['src/one.mjs']);
 assert.ok(p.chunks[0].privateDiffBytes.toString().includes(secret));
 assert.doesNotMatch(JSON.stringify(p),/SYNTHETIC_ONLY_SOURCE/);
 assert.doesNotMatch(JSON.stringify({...p}),/SYNTHETIC_ONLY_SOURCE/);
 assert.doesNotMatch(inspect(p),/SYNTHETIC_ONLY_SOURCE/);
 assert.doesNotMatch(inspect(p.chunks[0]),/SYNTHETIC_ONLY_SOURCE/);
 assert.ok(!Object.keys(p.chunks[0]).includes('privateDiffBytes'));
 assert.ok(Object.isFrozen(p));
});
test('never admit missing, reordered, duplicated or forged file scope',()=>{
 assert.throws(()=>run(diff,['src/one.mjs']),/REVIEW_SHARDS_FILE_COVERAGE_INVALID/);
 assert.throws(()=>run(diff,[...paths].reverse()),/REVIEW_SHARDS_FILE_COVERAGE_INVALID/);
 assert.throws(()=>run(diff,['src/one.mjs','src/one.mjs','src/three.mjs']),
  /REVIEW_SHARDS_SCOPE_UNVERIFIED/);
 assert.throws(()=>partitionBoundedGitDiff({
  rawDiffBytes:diff,trustedDiffSha256:'0'.repeat(64),
  trustedChangedPaths:paths
 }),/REVIEW_SHARDS_SCOPE_UNVERIFIED/);
});
test('oversized single file cannot be silently split or truncated',()=>{
 const source=Buffer.from(file('src/big.mjs','small()','X'.repeat(5000)));
 assert.throws(()=>run(source,['src/big.mjs'],{maxChunkBytes:3072}),
  /REVIEW_SHARDS_SINGLE_FILE_OVERSIZED/);
});
test('fail closed on malformed or binary diff without claiming partial coverage',()=>{
 const broken=Buffer.from(file('src/a.mjs').replace('+new()','+new()\n+unexpected'));
 assert.throws(()=>run(broken,['src/a.mjs']),/DIFF_ANCHOR_(?:HUNK_MISMATCH|FILE_INCOMPLETE)/);
 const binary=Buffer.from([255,0,4,13,255,0,19,255,255,255,255,255,255,255,255,255]);
 assert.throws(()=>run(binary,['src/a.mjs']),/REVIEW_SHARDS_ENCODING_UNSUPPORTED/);
});

test('lossless line-level spans cover an oversized file exactly, without implying model review',()=>{
 const big=Buffer.from(file('src/long.mjs','old()',
  Array.from({length:150},(_,i)=>'changed_'+i).join('\n+'))
  .replace('@@ -1 +1 @@','@@ -1 +1,150 @@'));
 assert.throws(()=>run(big,['src/long.mjs'],{maxChunkBytes:512}),
  /REVIEW_SHARDS_SINGLE_FILE_OVERSIZED/);
 const p=partitionLosslessDiffLines({
  rawDiffBytes:big,trustedDiffSha256:hash(big),
  trustedChangedPaths:['src/long.mjs'],maxSpanBytes:512
 });
 assert.ok(p.spanCount>1);
 assert.ok(p.spans.every(x=>x.byteCount<=512));
 assert.deepEqual([...new Set(p.spans.map(x=>x.path))],['src/long.mjs']);
 assert.ok(Buffer.concat(p.spans.map(x=>x.privateSliceBytes)).equals(big));
 assert.equal(p.byteCoverageComplete,true);
 assert.equal(p.semanticReviewCoverageVerified,false);
 assert.equal(p.approvalAuthorized,false);
 assert.equal(p.inferenceExecuted,false);
});
test('lossless span offsets have no gaps or overlaps across several files',()=>{
 const x=partitionLosslessDiffLines({
  rawDiffBytes:diff,trustedDiffSha256:hash(diff),
  trustedChangedPaths:paths,maxSpanBytes:512
 });
 assert.ok(x.spanCount>=1);
 assert.equal(x.spans[0].byteStart,0);
 assert.equal(x.spans.at(-1).byteEndExclusive,diff.length);
 for(let i=1;i<x.spanCount;i++)
  assert.equal(x.spans[i].byteStart,x.spans[i-1].byteEndExclusive);
});
test('lossless span mode refuses any single line over its maximum context',()=>{
 const huge=Buffer.from(file('src/huge.mjs','old()', 'x'.repeat(4000)));
 assert.throws(()=>partitionLosslessDiffLines({
  rawDiffBytes:huge,trustedDiffSha256:hash(huge),
  trustedChangedPaths:['src/huge.mjs'],maxSpanBytes:1024
 }),/REVIEW_SPANS_SINGLE_LINE_OVERSIZED/);
});
test('lossless spans redact source from JSON, object spread and inspect',()=>{
 const secret='SYNTHETIC_NEVER_PRIVATE_SPAN';
 const raw=Buffer.from(file('src/a.mjs','old()',secret));
 const o=partitionLosslessDiffLines({rawDiffBytes:raw,
  trustedDiffSha256:hash(raw),trustedChangedPaths:['src/a.mjs']});
 assert.ok(o.spans[0].privateSliceBytes.toString().includes(secret));
 assert.doesNotMatch(JSON.stringify(o),/SYNTHETIC_NEVER_PRIVATE_SPAN/);
 assert.doesNotMatch(JSON.stringify({...o}),/SYNTHETIC_NEVER_PRIVATE_SPAN/);
 assert.doesNotMatch(inspect(o),/SYNTHETIC_NEVER_PRIVATE_SPAN/);
 assert.ok(!Object.keys(o.spans[0]).includes('privateSliceBytes'));
});
test('lossless span mode rejects stale SHA and missing paths',()=>{
 assert.throws(()=>partitionLosslessDiffLines({
  rawDiffBytes:diff,trustedDiffSha256:'0'.repeat(64),
  trustedChangedPaths:paths
 }),/REVIEW_SPANS_SCOPE_UNVERIFIED/);
 assert.throws(()=>partitionLosslessDiffLines({
  rawDiffBytes:diff,trustedDiffSha256:hash(diff),
  trustedChangedPaths:paths.slice(1)
 }),/REVIEW_SPANS_FILE_COVERAGE_INVALID/);
});

test('CRLF diff sharding and spans preserve original SHA and every byte',()=>{
 const raw=Buffer.from(paths.map((p,i)=>file(p,'before'+i,'after'+i)).join('').replace(/\n/g,'\r\n'));
 const partition=run(raw,paths,{maxChunkBytes:512});
 assert.equal(partition.wholeDiffSha256,hash(raw));
 assert.equal(partition.coverageComplete,true);
 assert.ok(Buffer.concat(partition.chunks.map(x=>x.privateDiffBytes)).equals(raw));
 const spans=partitionLosslessDiffLines({rawDiffBytes:raw,
  trustedDiffSha256:hash(raw),trustedChangedPaths:paths,maxSpanBytes:512});
 assert.ok(Buffer.concat(spans.spans.map(x=>x.privateSliceBytes)).equals(raw));
 assert.equal(spans.approvalAuthorized,false);
 assert.equal(spans.semanticReviewCoverageVerified,false);
});
