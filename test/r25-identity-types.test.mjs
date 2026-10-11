import test from 'node:test';
import assert from 'node:assert/strict';
import { nativePayloadBytes } from '../src/native-review-wire.mjs';
import { deriveConsistentPrSnapshot } from '../src/pr-snapshot-consistency.mjs';
import { assessIndependentReviewCandidates } from '../candidate/independent-review-candidates.mjs';

const sha40 = 'a'.repeat(40);
const sha64 = 'b'.repeat(64);
const payload = () => ({
  app_bot_id:340237276,base_sha:sha40,completed_at:'2026-10-10T08:00:00Z',
  head_sha:sha40,installation_id:169674558,nonce:'c'.repeat(32),
  pr_number:898,provenance_ref:'fixture:synthetic-run-898',
  report_sha256:sha64,repository:'deenkids7-dev/deenkids',
  reviewer_run_id:'fixture-run-898',verdict:'PASS'
});
test('native signer bytes reject array-valued identity fields',()=>{
  for(const key of ['head_sha','base_sha','report_sha256','nonce','reviewer_run_id','provenance_ref']){
    const obj=payload(); obj[key]=[obj[key]];
    assert.throws(()=>nativePayloadBytes(obj),/NATIVE_INVALID_PAYLOAD/,key);
  }
});
const metadata = () => ({
  number:898,state:'open',merged_at:null,draft:false,changed_files:1,
  head:{sha:sha40,repo:{full_name:'deenkids7-dev/deenkids',id:1282086207}},
  base:{sha:sha40,ref:'master',repo:{full_name:'deenkids7-dev/deenkids',id:1282086207}}
});
const diff=Buffer.from('diff --git a/file.mjs b/file.mjs\nindex 0000000..1111111 100644\n--- a/file.mjs\n+++ b/file.mjs\n@@ -1 +1 @@\n-before\n+after\n');
test('snapshot rejects array-valued HEAD and BASE',()=>{
  for(const side of ['head','base']){
    const m=metadata();m[side].sha=[sha40];
    assert.throws(()=>deriveConsistentPrSnapshot({
      requestedPr:898,metadataBefore:m,metadataAfter:m,rawDiff:diff
    }),/GITHUB_PR_NOT_ELIGIBLE/,side);
  }
});
test('external-account candidate scope rejects array-valued expected SHA or eligible login',()=>{
  const opts={repository:'devfactory-reviewer-trust/devfactory-reviewer-b-publisher',
    prNumber:2,expectedHeadSha:sha40,reviews:[],
    eligibleReviewerLogins:['external-security-reviewer']};
  assert.throws(()=>assessIndependentReviewCandidates({...opts,
    expectedHeadSha:[sha40]}),/REVIEW_CANDIDATES_SCOPE_INVALID/);
  assert.throws(()=>assessIndependentReviewCandidates({...opts,
    eligibleReviewerLogins:[['external-security-reviewer']]}),
    /REVIEW_CANDIDATES_SCOPE_INVALID/);
});
