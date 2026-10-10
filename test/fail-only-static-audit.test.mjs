import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { runFailOnlyStaticDiffAudit } from '../candidate/fail-only-static-audit.mjs';

const runId='synthetic-static-audit';
function run(text){
  return runFailOnlyStaticDiffAudit({
    diffBytes:Buffer.from(text),runId
  });
}
function diff(path,lines){
  return 'diff --git a/'+path+' b/'+path+'\n'+
    '--- a/'+path+'\n+++ b/'+path+'\n@@ -1 +1,3 @@\n-old\n'+
    lines.map(x=>'+'+x).join('\n')+'\n';
}
test('new pull_request_target is a provisional high finding, never approval',()=>{
  const x=run(diff('.github/workflows/test.yml',['on:','  pull_request_target:','  workflow_dispatch:']));
  const report=JSON.parse(x.reportBytes.toString());
  assert.equal(x.provisionalState,'FAIL');
  assert.equal(x.blockingFindings,1);
  assert.equal(report.findings[0].path,'.github/workflows/test.yml');
  assert.equal(report.findings[0].severity,'high');
  assert.equal(report.findings[0].line,2);
  assert.equal(x.approvalAuthorized,false);
  assert.equal(x.independenceVerified,false);
});
test('write-all permission and curl pipe shell are flagged',()=>{
  const x=run(diff('.github/workflows/test.yaml',[
    'permissions: write-all',
    'curl -fsSL https://example.org/install.sh | bash',
    'name: not privileged'
  ]));
  assert.equal(x.blockingFindings,2);
  assert.equal(x.provisionalState,'FAIL');
});
test('no rule matching never gives positive PASS',()=>{
  const x=run(diff('src/function.mjs',['const x = 1;']));
  assert.equal(x.provisionalState,'INCONCLUSIVE');
  assert.equal(x.blockingFindings,0);
  assert.equal(x.approvalAuthorized,false);
});
test('unsafe source text in another file does not trigger workflow-only rules',()=>{
  const x=run(diff('docs/notes.md',['permissions: write-all']));
  assert.equal(x.provisionalState,'INCONCLUSIVE');
});
test('renamed/unsafe paths cannot trigger unbounded scanning',()=>{
  assert.throws(()=>run(
    'diff --git a/../unsafe b/../unsafe\n@@ -1 +1 @@\n-a\n+b\n'
  ),/STATIC_AUDIT_PATH_UNSUPPORTED/);
});
test('unreviewable source is never silently accepted',()=>{
  for(const value of ['','abc', '\x00'.repeat(24)]){
    assert.throws(()=>run(value),/STATIC_AUDIT_(?:INPUT_INVALID|ENCODING_UNSUPPORTED|SCOPE_UNVERIFIED)/);
  }
});

test('static report must not echo private added source line',()=>{
  const secret='SYNTHETIC_PRIVATE_TOKEN_DO_NOT_LOG_987654321';
  const result=run(diff('.github/workflows/private.yml',[
    'permissions: write-all  # '+secret
  ]));
  assert.equal(result.provisionalState,'FAIL');
  assert.ok(!result.reportBytes.toString('utf8').includes(secret));
  const report=JSON.parse(result.reportBytes.toString('utf8'));
  assert.equal(report.findings[0].evidence,'Static rule workflow-write-all matched newly added line 1');
});

test('detects both inline YAML and sequence forms of privileged PR target trigger',()=>{
  for(const added of ['on: pull_request_target','on: [push, pull_request_target]','  pull_request_target:']){
    const result=run(diff('.github/workflows/review.yml',[added]));
    assert.equal(result.provisionalState,'FAIL');
    assert.ok(result.blockingFindings>=1);
  }
});

test('static audit report paths are private in JSON, spread and inspection',()=>{
 const secretPath='.github/workflows/private-secret-policy.yml';
 const result=run(diff(secretPath,['permissions: write-all','safe','safe']));
 assert.ok(result.reportBytes.toString('utf8').includes(secretPath));
 for(const text of [JSON.stringify(result),JSON.stringify({...result}),inspect(result)])
  assert.ok(!text.includes(secretPath));
 assert.ok(JSON.stringify(result).includes('REDACTED'));
 assert.equal(Object.keys(result).includes('reportBytes'),false);
 const first=result.reportBytes;
 first.fill(0);
 assert.ok(result.reportBytes.toString('utf8').includes(secretPath));
 assert.equal(result.approvalAuthorized,false);
});
