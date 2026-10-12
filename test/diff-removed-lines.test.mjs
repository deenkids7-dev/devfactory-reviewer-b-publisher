import test from 'node:test';
import assert from 'node:assert/strict';
import {deriveRemovedLinesFromDiff,isRemovedLine}
 from '../candidate/diff-removed-lines.mjs';
const header=p=>'diff --git a/'+p+' b/'+p+'\n'+
 'index 1234567..abcdef0 100644\n--- a/'+p+'\n+++ b/'+p+'\n';
const old=x=>deriveRemovedLinesFromDiff({diffBytes:Buffer.from(x)});
test('R75 deleted OLD-side locations preserve original numbering across hunks',()=>{
 const source=header('src/auth.mjs')+
  '@@ -8,3 +8,3 @@\n unchanged\n-oldGuardA\n+newGuardA\n unchangedAgain\n'+
  '@@ -33,2 +33,1 @@\n-oldGuardB\n retained\n';
 const found=old(source);
 assert.deepEqual(found['src/auth.mjs'],[9,33]);
 assert.equal(isRemovedLine({anchors:found,path:'src/auth.mjs',line:9}),true);
 assert.equal(isRemovedLine({anchors:found,path:'src/auth.mjs',line:33}),true);
 assert.equal(isRemovedLine({anchors:found,path:'src/auth.mjs',line:8}),false);
 assert.equal(isRemovedLine({anchors:found,path:'src/auth.mjs',line:10}),false);
 assert.equal(isRemovedLine({anchors:found,path:'src/other.mjs',line:9}),false);
 assert.equal(Object.isFrozen(found),true);
});
test('R75 deletion-only hunk including removed file reports OLD coordinate',()=>{
 const source='diff --git a/old.mjs b/old.mjs\n'+
  'deleted file mode 100644\n--- a/old.mjs\n+++ /dev/null\n'+
  '@@ -1,2 +0,0 @@\n-remove1\n-remove2\n';
 assert.deepEqual(old(source)['old.mjs'],[1,2]);
});
test('R75 never derives OLD anchors from malformed or mismatched hunk structure',()=>{
 const cases=[
  header('src/auth.mjs')+'@@ -1,2 +1,0 @@\n-onlyOne\n',
  header('src/auth.mjs')+'@@ -1 +1 @@\n-old\n+new\n-extra\n',
  header('src/auth.mjs')+'@@ -0 +1 @@\n-old\n+new\n'
 ];
 for(const source of cases)
  assert.throws(()=>old(source),/DIFF_ANCHOR_|DIFF_OLD_ANCHOR_/);
});
