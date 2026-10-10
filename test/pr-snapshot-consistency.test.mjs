import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { deriveConsistentPrSnapshot as snapshot } from '../src/pr-snapshot-consistency.mjs';

const h = 'a'.repeat(40);
const b = 'b'.repeat(40);
const diff = Buffer.from('diff --git a/file.mjs b/file.mjs\nindex 0000000..1111111 100644\n--- a/file.mjs\n+++ b/file.mjs\n@@ -1 +1 @@\n-before\n+after\n');
const metadata = () => ({
  number:898,state:'open',merged_at:null,draft:false,changed_files:1,
  head:{sha:h},base:{sha:b,ref:'master',repo:{
    full_name:'deenkids7-dev/deenkids',id:1282086207
  }}
});
const fixture=(changes={})=>({
  requestedPr:898,metadataBefore:metadata(),metadataAfter:metadata(),rawDiff:diff,...changes
});
function rejects(name,changes,code){
  test(name,()=>assert.throws(()=>snapshot(fixture(changes)),e=>e.message===code));
}
test('hashes exact stable synthetic diff; does NOT attest GitHub provenance',()=>{
  const actual=snapshot(fixture());
  assert.deepEqual(actual,{
    repository:'deenkids7-dev/deenkids',repository_id:1282086207,
    pr_number:898,head_sha:h,base_sha:b,
    diff_sha256:createHash('sha256').update(diff).digest('hex')
  });
  assert.ok(Object.isFrozen(actual));
});
rejects('rejects moved HEAD', {
  metadataAfter:{...metadata(),head:{sha:'c'.repeat(40)}}
},'GITHUB_PR_CHANGED_DURING_READ');
rejects('rejects moved BASE', {
  metadataAfter:{...metadata(),base:{...metadata().base,sha:'c'.repeat(40)}}
},'GITHUB_PR_CHANGED_DURING_READ');
rejects('rejects different repo', {
  metadataBefore:{...metadata(),base:{...metadata().base,repo:{
    full_name:'someone/else',id:1282086207
  }}}
},'GITHUB_PR_NOT_ELIGIBLE');
rejects('rejects wrong repo ID', {
  metadataBefore:{...metadata(),base:{...metadata().base,repo:{
    full_name:'deenkids7-dev/deenkids',id:100
  }}}
},'GITHUB_PR_NOT_ELIGIBLE');
rejects('rejects draft PR', {
  metadataBefore:{...metadata(),draft:true}
},'GITHUB_PR_NOT_ELIGIBLE');
rejects('rejects closed PR', {
  metadataBefore:{...metadata(),state:'closed'}
},'GITHUB_PR_NOT_ELIGIBLE');
rejects('rejects wrong PR', {
  metadataBefore:{...metadata(),number:899}
},'GITHUB_PR_NOT_ELIGIBLE');
rejects('rejects wrong base branch', {
  metadataBefore:{...metadata(),base:{...metadata().base,ref:'release'}}
},'GITHUB_PR_NOT_ELIGIBLE');
rejects('rejects diff without a hunk', {
  rawDiff:Buffer.from('diff --git a/f b/f\n--- a/f\n+++ b/f\n')
},'GITHUB_DIFF_COVERAGE_UNVERIFIED');
rejects('rejects truncated diff with 2 files expected', {
  metadataBefore:{...metadata(),changed_files:2},
  metadataAfter:{...metadata(),changed_files:2}
},'GITHUB_DIFF_COVERAGE_UNVERIFIED');
rejects('rejects unsupported binary changes', {
  rawDiff:Buffer.from('diff --git a/img b/img\nBinary files a/img and b/img differ\n@@ -1 +1 @@\n-a\n+b\n')
},'GITHUB_DIFF_ENCODING_OR_BINARY_UNSUPPORTED');
rejects('rejects oversized diff', {
  rawDiff:Buffer.alloc(2*1024*1024+1,65)
},'GITHUB_DIFF_BYTES_UNSUPPORTED');
rejects('rejects malformed UTF8 diff', {
  rawDiff:Buffer.from([0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff])
},'GITHUB_DIFF_ENCODING_OR_BINARY_UNSUPPORTED');
rejects('rejects noninteger PR selector', {
  requestedPr:'898'
},'GITHUB_PR_NOT_ELIGIBLE');
test('rejects untrusted null metadata',()=>{
  assert.throws(()=>snapshot(fixture({metadataBefore:null})),
    e=>e.message==='INVALID_GITHUB_PR_METADATA');
});
