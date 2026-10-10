import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveAddedLinesFromDiff,isAddedLine } from '../candidate/diff-added-lines.mjs';
const hdr=p=>'diff --git a/'+p+' b/'+p+'\n'+
 'index 0123456..abcdef0 100644\n--- a/'+p+'\n+++ b/'+p+'\n';
const parse=s=>deriveAddedLinesFromDiff({diffBytes:Buffer.from(s)});
test('source additions anchor only the newly added lines across multiple hunks',()=>{
 const x=parse(hdr('src/demo.mjs')+
 '@@ -4,3 +4,4 @@\n context\n-old\n+new\n+extra\n context2\n'+
 '@@ -20,2 +21,2 @@\n gone\n-old2\n+new2\n');
 assert.deepEqual(x['src/demo.mjs'],[5,6,22]);
 assert.equal(isAddedLine({anchors:x,path:'src/demo.mjs',line:5}),true);
 assert.equal(isAddedLine({anchors:x,path:'src/demo.mjs',line:4}),false);
 assert.equal(isAddedLine({anchors:x,path:'other',line:5}),false);
});
test('deletion-only PR cannot fabricate an added-line citation',()=>{
 const x=parse(hdr('src/file.mjs')+'@@ -1 +0,0 @@\n-old\n');
 assert.deepEqual(x['src/file.mjs'],[]);
});
test('reject incomplete or oversized hunk declarations',()=>{
 for(const source of [
  hdr('src/a.mjs')+'@@ -1,2 +1,2 @@\n-old\n+new\n',
  hdr('src/a.mjs')+'@@ -1 +1 @@\n-old\n+new\n+extra\n',
  hdr('src/a.mjs')+'@@ broken @@\n-old\n+new\n'
 ])assert.throws(()=>parse(source),/DIFF_ANCHOR_/);
});
test('reject duplicate/unsafe names instead of silently merging sources',()=>{
 assert.throws(()=>parse(hdr('src/a.mjs')+'@@ -1 +1 @@\n-a\n+b\n'+
  hdr('src/a.mjs')+'@@ -1 +1 @@\n-c\n+d\n'),/DIFF_ANCHOR_PATH_INVALID/);
 assert.throws(()=>parse('diff --git a/../x b/../x\n@@ -1 +1 @@\n-x\n+y\n'),
  /DIFF_ANCHOR_PATH_INVALID/);
});
test('reject invalid UTF-8 or binary input',()=>{
 assert.throws(()=>deriveAddedLinesFromDiff({diffBytes:Buffer.from([255,0,7])}),
  /DIFF_ANCHOR_/);
});

test('line-anchor parser rejects overlapping or decreasing hunk coordinates',()=>{
 const h=hdr('src/overlap.mjs');
 for(const caseText of [
  '@@ -1 +1 @@\n-old\n+new\n@@ -1 +1 @@\n-old2\n+new2\n',
  '@@ -9 +9 @@\n-a\n+b\n@@ -2 +2 @@\n-a\n+b\n',
  '@@ -0 +1 @@\n-old\n+new\n',
  '@@ -1 +0 @@\n-old\n+new\n'
 ])assert.throws(()=>parse(h+caseText),/DIFF_ANCHOR_HUNK_ORDER_INVALID/);
});
test('zero-span new/deleted-file coordinates remain supported',()=>{
 const add=parse('diff --git a/new.mjs b/new.mjs\n'+
  'new file mode 100644\n--- /dev/null\n+++ b/new.mjs\n'+
  '@@ -0,0 +1 @@\n+new\n');
 assert.deepEqual(add['new.mjs'],[1]);
 const del=parse('diff --git a/old.mjs b/old.mjs\n'+
  'deleted file mode 100644\n--- a/old.mjs\n+++ /dev/null\n'+
  '@@ -1 +0,0 @@\n-old\n');
 assert.deepEqual(del['old.mjs'],[]);
});
