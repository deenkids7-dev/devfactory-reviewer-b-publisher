import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../src/canonical.mjs';
import { validateReviewerFindings } from '../src/findings-contract.mjs';
import { normalizeUntrustedModelFindings, prepareBoundedSemanticReview } from '../candidate/semantic-review-request.mjs';

const finding=()=>({fingerprint:'a'.repeat(64),severity:'high',path:'src/a.mjs',line:1,message:'Synthetic',evidence:'Synthetic only'});
const report=(overrides={})=>Buffer.from(canonicalJson({
  schema:'devfactory.reviewer-b.findings.v1',
  run_id:'synthetic-run-001',summary:'Synthetic only',
  findings:[finding()],...overrides
}));
test('rejects array run_id in canonical reviewer report',()=>{
  assert.throws(()=>validateReviewerFindings({
    reportBytes:report({run_id:['synthetic-run-001']}),
    changedPaths:['src/a.mjs']
  }),/REVIEW_INVALID_FIELDS/);
});
test('rejects array fingerprint in canonical reviewer report',()=>{
  assert.throws(()=>validateReviewerFindings({
    reportBytes:report({findings:[{...finding(),fingerprint:['a'.repeat(64)]}]}),
    changedPaths:['src/a.mjs']
  }),/REVIEW_FINDING_INVALID/);
});
test('rejects array trusted runId in semantic normalization',()=>{
  assert.throws(()=>normalizeUntrustedModelFindings({
    rawModelOutput:JSON.stringify({summary:'Synthetic only',findings:[]}),
    runId:['synthetic-run-001'],trustedChangedPaths:['src/a.mjs']
  }),/SEMANTIC_MODEL_OUTPUT_INVALID/);
});
test('rejects array head/base SHA in semantic request snapshot',()=>{
  const diff=Buffer.from('diff --git a/src/a.mjs b/src/a.mjs\n@@ -1 +1 @@\n-a\n+b\n');
  const snapshot={
    repository:'deenkids7-dev/deenkids',repository_id:1282086207,
    pr_number:898,head_sha:['a'.repeat(40)],base_sha:['b'.repeat(40)],
    diff_sha256:createHash('sha256').update(diff).digest('hex')
  };
  assert.throws(()=>prepareBoundedSemanticReview({snapshot,rawDiffBytes:diff}),
    /SEMANTIC_REVIEW_SCOPE_UNVERIFIED/);
});
