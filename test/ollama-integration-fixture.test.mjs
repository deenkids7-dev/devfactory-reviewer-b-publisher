import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { runFailOnlyStaticDiffAudit } from '../candidate/fail-only-static-audit.mjs';
import { prepareBoundedSemanticReview } from '../candidate/semantic-review-request.mjs';
import {
  prepareOfflineOllamaCandidate,validateOfflineOllamaCompletion
} from '../candidate/ollama-offline-contract.mjs';
import { combineReviewerFindings } from '../candidate/combine-findings.mjs';

const runId='offline-ollama-integration-fixture';
const path='.github/workflows/synthetic.yml';
const digest=v=>createHash('sha256').update(v).digest('hex');
function fixture(trigger='contents: read') {
  const diff=Buffer.from(
    'diff --git a/'+path+' b/'+path+'\n'+
    'index 1234567..abcdef0 100644\n--- a/'+path+'\n'+
    '+++ b/'+path+'\n@@ -1 +1 @@\n-name: before\n+'+trigger+'\n'
  );
  const target={
    repository:'deenkids7-dev/deenkids',repository_id:1282086207,
    pr_number:898,head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),
    diff_sha256:digest(diff)
  };
  const staticAudit=runFailOnlyStaticDiffAudit({diffBytes:diff,runId});
  const plan=prepareBoundedSemanticReview({snapshot:target,rawDiffBytes:diff});
  const candidate=prepareOfflineOllamaCandidate({plan});
  return {staticAudit,plan,candidate,diff};
}
function analyze(f,findings=[]) {
  const completion=validateOfflineOllamaCompletion({
    response:{
      model:'qwen2.5-coder:7b',done:true,done_reason:'stop',
      message:{role:'assistant',content:JSON.stringify({
        summary:'Synthetic model response, not a real independent review',
        findings
      })},prompt_eval_count:800,eval_count:160
    },
    expectedModel:'qwen2.5-coder:7b',runId,
    trustedChangedPaths:f.plan.changedPaths,
    trustedDiffBytes:f.diff,expectedDiffSha256:digest(f.diff),
    maxPromptTokens:1000,maxCompletionTokens:512
  });
  return combineReviewerFindings({
    staticReportBytes:f.staticAudit.reportBytes,
    semanticReportBytes:completion.privateCanonicalReportBytes,
    changedPaths:f.plan.changedPaths
  });
}
test('a clean fake local-model completion cannot erase static audit blocker',()=>{
  const f=fixture('on: [pull_request_target]');
  const result=analyze(f);
  assert.equal(f.staticAudit.blockingFindings,1);
  assert.equal(result.blockingFindings,1);
  assert.equal(result.provisionalState,'FAIL');
  assert.equal(result.independentReviewVerified,false);
  assert.equal(result.approvalAuthorized,false);
  assert.equal(result.publishEvent,null);
  assert.equal(f.candidate.modelExecuted,false);
});
test('clean synthetic local-model path stays INCONCLUSIVE, never PASS',()=>{
  const result=analyze(fixture());
  assert.equal(result.blockingFindings,0);
  assert.equal(result.provisionalState,'INCONCLUSIVE');
  assert.equal(result.approvalAuthorized,false);
});
test('a semantic issue is preserved by the common findings contract',()=>{
  const f=fixture();
  const result=analyze(f,[{
    severity:'high',path,line:1,
    message:'Seeded synthetic issue',evidence:'Artificial test only'
  }]);
  const parsed=JSON.parse(result.reportBytes.toString('utf8'));
  assert.equal(result.blockingFindings,1);
  assert.equal(parsed.findings.length,1);
  assert.equal(parsed.findings[0].severity,'high');
  assert.equal(result.provisionalState,'FAIL');
});
