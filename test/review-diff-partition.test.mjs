import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { partitionBoundedGitDiff } from '../candidate/review-diff-partition.mjs';

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
