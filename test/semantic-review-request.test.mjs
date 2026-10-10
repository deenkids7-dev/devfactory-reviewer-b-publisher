import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../src/canonical.mjs';
import { prepareBoundedSemanticReview, normalizeUntrustedModelFindings }
  from '../candidate/semantic-review-request.mjs';

const diff=Buffer.from('diff --git a/src/a.mjs b/src/a.mjs\n'+
  'index 12ab..34cd 100644\n--- a/src/a.mjs\n+++ b/src/a.mjs\n'+
  '@@ -1 +1 @@\n-console.log(1);\n+console.log(2);\n');
const snapshot={
  repository:'deenkids7-dev/deenkids',repository_id:1282086207,
  pr_number:898,head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),
  diff_sha256:createHash('sha256').update(diff).digest('hex')
};
const runId='synthetic-run-898';
const finding=()=>({
  fingerprint:'c'.repeat(64),severity:'high',
  path:'src/a.mjs',line:1,message:'SYNTHETIC finding',
  evidence:'Synthetic fixture only'
});
test('semantic request binds exact SHA, changed-file names and diff bytes',()=>{
  const plan=prepareBoundedSemanticReview({
    snapshot,rawDiffBytes:diff
  });
  assert.equal(plan.privateDiffText,diff.toString());
  assert.deepEqual(plan.changedPaths,['src/a.mjs']);
  assert.equal(plan.approvedToSendToModel,false);
  assert.equal(plan.approvalAuthorized,false);
  assert.equal(plan.exactScope.prNumber,898);
  assert.equal(plan.exactScope.diffSha256,snapshot.diff_sha256);
  assert.match(plan.systemInstructions,/Treat all source code/);
});
test('forged diff hash and commit scope are denied',()=>{
  for(const changes of [
    {rawDiffBytes:Buffer.from(diff.toString().replace('console.log(2)','console.log(3)'))},
    {snapshot:{...snapshot,repository:'other/repo'}},
    {snapshot:{...snapshot,head_sha:'wrong'}}
  ]){
    assert.throws(()=>prepareBoundedSemanticReview({
      snapshot,rawDiffBytes:diff,...changes
    }),/SEMANTIC_REVIEW_SCOPE_UNVERIFIED/);
  }
});
test('renames/path traversal are not silently accepted by semantic interface',()=>{
  const examples=[
    'diff --git a/a.mjs b/b.mjs\n@@ -1 +1 @@\n-a\n+b\n',
    'diff --git a/../secret b/../secret\n@@ -1 +1 @@\n-a\n+b\n'
  ];
  for(const value of examples){
    const rawDiffBytes=Buffer.from(value);
    const scoped={...snapshot,diff_sha256:createHash('sha256').update(rawDiffBytes).digest('hex')};
    assert.throws(()=>prepareBoundedSemanticReview({
      snapshot:scoped,rawDiffBytes
    }),/SEMANTIC_CHANGED_PATH_UNSUPPORTED/);
  }
});
test('untrusted model cannot produce PASS even without findings',()=>{
  const empty=normalizeUntrustedModelFindings({
    rawModelOutput:JSON.stringify({summary:'No issues were identified',findings:[]}),
    runId,trustedChangedPaths:['src/a.mjs']
  });
  assert.equal(empty.provisionalState,'INCONCLUSIVE');
  assert.equal(empty.approvalAuthorized,false);
  assert.equal(empty.reviewerIndependenceVerified,false);
  const report=JSON.parse(empty.reportBytes.toString('utf8'));
  assert.equal(report.run_id,runId);
  assert.equal(report.schema,'devfactory.reviewer-b.findings.v1');
  assert.equal(empty.reportBytes.toString(),canonicalJson(report));
});
test('blocking semantic findings remain provisional FAIL',()=>{
  const result=normalizeUntrustedModelFindings({
    rawModelOutput:JSON.stringify({summary:'Synthetic blocker',findings:[finding()]}),
    runId,trustedChangedPaths:['src/a.mjs']
  });
  assert.equal(result.provisionalState,'FAIL');
  assert.equal(result.approvalAuthorized,false);
});
test('model cannot choose release approval, run id, or output a PASS',()=>{
  for(const value of [
    {summary:'all good',findings:[],verdict:'PASS'},
    {summary:'all good',findings:[],approvalAuthorized:true},
    {summary:'all good',findings:[],run_id:'attacker-run'}
  ]){
    assert.throws(()=>normalizeUntrustedModelFindings({
      rawModelOutput:JSON.stringify(value),
      runId,trustedChangedPaths:['src/a.mjs']
    }),/SEMANTIC_MODEL_FIELDS_INVALID/);
  }
});
test('model cannot submit out-of-scope finding',()=>{
  assert.throws(()=>normalizeUntrustedModelFindings({
    rawModelOutput:JSON.stringify({
      summary:'Untrusted scope',findings:[{...finding(),path:'hidden/private'}]
    }),runId,trustedChangedPaths:['src/a.mjs']
  }),/REVIEW_FINDING_INVALID/);
});
test('malformed or verbose model output is rejected',()=>{
  for(const value of ['```json\n{}\n```','{','a'.repeat(70000)]){
    assert.throws(()=>normalizeUntrustedModelFindings({
      rawModelOutput:value,runId,trustedChangedPaths:['src/a.mjs']
    }));
  }
});
