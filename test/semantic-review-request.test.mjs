import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
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
test('authenticated CRLF diff parses paths without changing signed bytes',()=>{
  const crlf=Buffer.from(diff.toString('utf8').replace(/\n/g,'\r\n'));
  const scoped={...snapshot,
    diff_sha256:createHash('sha256').update(crlf).digest('hex')
  };
  const plan=prepareBoundedSemanticReview({
    snapshot:scoped,rawDiffBytes:crlf
  });
  assert.deepEqual(plan.changedPaths,['src/a.mjs']);
  assert.equal(plan.privateDiffText,crlf.toString('utf8'));
  assert.equal(plan.exactScope.diffSha256,scoped.diff_sha256);
  assert.equal(plan.approvedToSendToModel,false);
});

test('stray CR is denied instead of altering line boundaries',()=>{
  const malformed=Buffer.from(diff.toString('utf8').replace(
    'diff --git a/src/a.mjs b/src/a.mjs\n',
    'diff --git a/src/a.mjs b/src/a.mjs\r'
  ));
  const scoped={...snapshot,
    diff_sha256:createHash('sha256').update(malformed).digest('hex')
  };
  assert.throws(()=>prepareBoundedSemanticReview({
    snapshot:scoped,rawDiffBytes:malformed
  }),/SEMANTIC_DIFF_UNSUPPORTED/);
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

test('private diff review plan redacts accidental JSON and debug inspection',()=>{
  const confidential=Buffer.from(
    'diff --git a/src/secret.mjs b/src/secret.mjs\n'+
    'index 111..222 100644\n--- a/src/secret.mjs\n'+
    '+++ b/src/secret.mjs\n@@ -1 +1 @@\n'+
    '-old\n+SYNTHETIC_PRIVATE_LITERAL_NEVER_PRINT\n'
  );
  const scoped={...snapshot,
    diff_sha256:createHash('sha256').update(confidential).digest('hex')
  };
  const plan=prepareBoundedSemanticReview({
    snapshot:scoped,rawDiffBytes:confidential
  });
  assert.ok(plan.privateDiffText.includes('SYNTHETIC_PRIVATE_LITERAL_NEVER_PRINT'));
  assert.ok(!JSON.stringify(plan).includes('SYNTHETIC_PRIVATE_LITERAL_NEVER_PRINT'));
  assert.ok(!inspect(plan).includes('SYNTHETIC_PRIVATE_LITERAL_NEVER_PRINT'));
  assert.equal(JSON.parse(JSON.stringify(plan)).privateDiffText,'[REDACTED]');
  assert.ok(!Object.keys(plan).includes('privateDiffText'));
  assert.ok(!JSON.stringify({...plan}).includes('SYNTHETIC_PRIVATE_LITERAL_NEVER_PRINT'));
  assert.ok(!JSON.stringify(Object.assign({},plan)).includes('SYNTHETIC_PRIVATE_LITERAL_NEVER_PRINT'));
  assert.ok(!JSON.stringify(structuredClone(plan)).includes('SYNTHETIC_PRIVATE_LITERAL_NEVER_PRINT'));
  assert.ok(Object.isFrozen(plan));
});

test('untrusted semantic report never leaks private messages in JSON or inspect',()=>{
 const secret='SYNTHETIC_SECRET_SEMANTIC_MESSAGE';
 const value=normalizeUntrustedModelFindings({
  rawModelOutput:JSON.stringify({summary:secret,findings:[]}),
  runId,trustedChangedPaths:['src/a.mjs']
 });
 assert.ok(value.reportBytes.toString().includes(secret));
 assert.doesNotMatch(JSON.stringify(value),/SYNTHETIC_SECRET_SEMANTIC_MESSAGE/);
 assert.doesNotMatch(JSON.stringify({...value}),/SYNTHETIC_SECRET_SEMANTIC_MESSAGE/);
 assert.doesNotMatch(inspect(value),/SYNTHETIC_SECRET_SEMANTIC_MESSAGE/);
 assert.match(JSON.stringify(value),/REDACTED_PRIVATE_REPORT/);
 const copy=value.reportBytes;copy.fill(0);
 assert.ok(value.reportBytes.toString().includes(secret));
});
