import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {inspect} from 'node:util';
import {prepareBoundedSemanticReview} from '../candidate/semantic-review-request.mjs';
import {makeBoundedDiffDeclarationIndex,verifiedDiffDeclarationSummary}
 from '../candidate/semantic-diff-declarations.mjs';
import {prepareOfflineOllamaCandidate}
 from '../candidate/ollama-offline-contract.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const HEAD='a'.repeat(40),BASE='b'.repeat(40);
function file(path,body,oldCount,newCount){
 return 'diff --git a/'+path+' b/'+path+'\n'+
  'index 1234567..abcdef0 100644\n--- a/'+path+'\n'+
  '+++ b/'+path+'\n@@ -1,'+oldCount+' +1,'+newCount+' @@\n'+body;
}
const original=Buffer.from(
 file('src/functions.mjs',
  ' old\n+function githubJson() {}\n+const exactCI=()=>true;\n'+
  '+import {assessOperatorDualReview} from "./policy.mjs";\n',1,4)+
 file('src/use.mjs',' old\n+githubJson();\n',1,2)
);
function plan(bytes=original){
 return prepareBoundedSemanticReview({
  snapshot:{repository:'deenkids7-dev/deenkids',repository_id:1282086207,
   pr_number:904,head_sha:HEAD,base_sha:BASE,diff_sha256:sha(bytes)},
  rawDiffBytes:bytes
 });
}
test('R73 full authenticated diff yields names missing from an individual shard',()=>{
 const index=makeBoundedDiffDeclarationIndex({plan:plan()});
 assert.equal(index.entryCount,3);
 assert.equal(index.modelContextCompletenessVerified,false);
 assert.equal(index.approvalAuthorized,false);
 const shard=plan(Buffer.from(file('src/use.mjs',' old\n+githubJson();\n',1,2)));
 const req=prepareOfflineOllamaCandidate({
  plan:shard,trustedDeclarationIndex:index,maxOutputTokens:1024
 });
 const request=JSON.parse(req.privateRequestJson);
 const input=JSON.parse(request.messages[1].content);
 assert.equal(req.diffDeclarationContext,'BOUNDED_INCLUDED');
 assert.match(input.authenticated_full_diff_declarations,/functions\.mjs:function githubJson/);
 assert.match(input.authenticated_full_diff_declarations,/functions\.mjs:const exactCI/);
 assert.match(input.authenticated_full_diff_declarations,/functions\.mjs:import assessOperatorDualReview/);
 assert.match(request.messages[0].content,/lexical scope and imports are not proven/);
 assert.equal(input.untrusted_unified_diff,shard.privateDiffText);
 assert.doesNotMatch(JSON.stringify(index),/githubJson|exactCI|assessOperatorDualReview/);
 assert.doesNotMatch(inspect(index),/githubJson|exactCI|assessOperatorDualReview/);
});
test('R73 rejects forged declaration summaries, moved HEAD and malformed diffs',()=>{
 const index=makeBoundedDiffDeclarationIndex({plan:plan()});
 const shard=plan(Buffer.from(file('src/use.mjs',' old\n+githubJson();\n',1,2)));
 const forged={...index,privateSummary:'FAKE_FUNCTION_EXISTS'};
 assert.throws(()=>prepareOfflineOllamaCandidate({
  plan:shard,trustedDeclarationIndex:forged
 }),/DIFF_DECLARATIONS_UNTRUSTED/);
 const wrong=prepareBoundedSemanticReview({
  snapshot:{repository:'deenkids7-dev/deenkids',repository_id:1282086207,
   pr_number:904,head_sha:'c'.repeat(40),base_sha:BASE,
   diff_sha256:sha(Buffer.from(file('src/use.mjs',' old\n+githubJson();\n',1,2)))},
  rawDiffBytes:Buffer.from(file('src/use.mjs',' old\n+githubJson();\n',1,2))
 });
 assert.throws(()=>verifiedDiffDeclarationSummary({index,plan:wrong}),
  /DIFF_DECLARATIONS_UNTRUSTED/);
 const tampered={...plan(),privateDiffText:'not a canonical git diff'};
 assert.throws(()=>makeBoundedDiffDeclarationIndex({plan:tampered}),
  /DIFF_DECLARATIONS_UNTRUSTED/);
});
test('R73 declaration index never includes literal variable values or claims full-file coverage',()=>{
 const bytes=Buffer.from(file('src/config.mjs',
  ' old\n+const apiToken = "PRIVATE_EXAMPLE_LITERAL";\n',1,2));
 const index=makeBoundedDiffDeclarationIndex({plan:plan(bytes)});
 const summary=verifiedDiffDeclarationSummary({index,plan:plan(bytes)});
 assert.match(summary,/config\.mjs:const apiToken/);
 assert.doesNotMatch(summary,/PRIVATE_EXAMPLE_LITERAL/);
 assert.match(summary,/no complete file/);
 assert.equal(index.modelContextCompletenessVerified,false);
});
