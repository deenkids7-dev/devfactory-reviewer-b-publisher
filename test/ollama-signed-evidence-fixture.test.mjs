import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash,generateKeyPairSync } from 'node:crypto';
import { runFailOnlyStaticDiffAudit } from '../candidate/fail-only-static-audit.mjs';
import { prepareBoundedSemanticReview } from '../candidate/semantic-review-request.mjs';
import {
  prepareOfflineOllamaCandidate,validateOfflineOllamaCompletion
} from '../candidate/ollama-offline-contract.mjs';
import { combineReviewerFindings } from '../candidate/combine-findings.mjs';
import { signAnalyzerAttestationFixture } from '../candidate/analyzer-attestation-sign.mjs';
import { verifyReviewEvidence } from '../src/evidence-preflight.mjs';

const id='synthetic-ollama-signed-integration-898';
const path='.github/workflows/guard-synthetic.yml';
const sha=x=>createHash('sha256').update(x).digest('hex');
const pair=generateKeyPairSync('ed25519');
const privatePem=pair.privateKey.export({format:'pem',type:'pkcs8'});
const publicPem=pair.publicKey.export({format:'pem',type:'spki'});
const fingerprint=sha(pair.publicKey.export({format:'der',type:'spki'}));
const now=Date.parse('2026-10-10T08:02:00Z');
const nonce='11111111-2222-4333-8444-555555555555';
function stage(added){
 const diff=Buffer.from('diff --git a/'+path+' b/'+path+'\n'+
  'index 1234567..abcdef0 100644\n--- a/'+path+'\n'+
  '+++ b/'+path+'\n@@ -1 +1 @@\n-name: original\n+'+added+'\n');
 const target={
  repository:'deenkids7-dev/deenkids',repository_id:1282086207,
  pr_number:898,head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),
  diff_sha256:sha(diff)
 };
 const plan=prepareBoundedSemanticReview({snapshot:target,rawDiffBytes:diff});
 const staticAudit=runFailOnlyStaticDiffAudit({diffBytes:diff,runId:id});
 const candidate=prepareOfflineOllamaCandidate({plan});
 const content=JSON.stringify({summary:'Synthetic model completion only',findings:[]});
 const completion=validateOfflineOllamaCompletion({
  response:{
   model:'qwen2.5-coder:7b',done:true,done_reason:'stop',
   message:{role:'assistant',content},
   prompt_eval_count:500,eval_count:140
  },
  expectedModel:'qwen2.5-coder:7b',runId:id,
  trustedChangedPaths:plan.changedPaths,
  trustedDiffBytes:diff,expectedDiffSha256:target.diff_sha256,
  maxPromptTokens:1000,maxCompletionTokens:512
 });
 const combined=combineReviewerFindings({
  staticReportBytes:staticAudit.reportBytes,
  semanticReportBytes:completion.privateCanonicalReportBytes,
  changedPaths:plan.changedPaths
 });
 const attested=signAnalyzerAttestationFixture({
  reportBytes:combined.reportBytes,changedPaths:plan.changedPaths,
  target,runId:id,issuer:'synthetic-independent-engine',
  reviewerId:'synthetic-ollama-runner',keyId:'synthetic-ed25519',
  ed25519PrivateKeyPem:privatePem,pinnedEd25519SpkiSha256:fingerprint,
  nonce,issuedAt:'2026-10-10T08:00:00Z',
  expiresAt:'2026-10-10T08:10:00Z',now
 });
 return {diff,target,plan,candidate,staticAudit,completion,combined,attested};
}
function verify(d,seenNonces=new Set()){
 return verifyReviewEvidence({
  envelopeBytes:d.attested.envelopeBytes,
  reportBytes:d.combined.reportBytes,
  trustedKeys:new Map([['synthetic-ed25519',{
   issuer:'synthetic-independent-engine',
   reviewerId:'synthetic-ollama-runner',
   publicKeyPem,spkiSha256:fingerprint
  }]]),
  trustedTarget:d.target,trustedChangedPaths:d.plan.changedPaths,
  seenReviewIds:new Set(),seenNonces,now
 });
}
test('realistic synthetic high-risk diff flows to signed FAIL, NEVER GitHub publish',()=>{
 const r=stage('pull_request_target:');
 assert.equal(r.staticAudit.blockingFindings,1);
 assert.equal(r.combined.provisionalState,'FAIL');
 assert.equal(r.attested.signedDisposition,'FAIL');
 const checked=verify(r);
 assert.equal(checked.signatureVerified,true);
 assert.equal(checked.provisionalState,'FAIL');
 assert.equal(checked.independenceVerified,false);
 assert.equal(checked.approvalAuthorized,false);
 assert.equal(r.candidate.modelExecuted,false);
 assert.equal(r.candidate.publishEvent,null);
 assert.equal(r.combined.publishEvent,null);
});
test('synthetic safe diff remains INCONCLUSIVE and signs BLOCKED, never PASS',()=>{
 const r=stage('contents: read');
 assert.equal(r.staticAudit.blockingFindings,0);
 assert.equal(r.combined.blockingFindings,0);
 assert.equal(r.attested.signedDisposition,'BLOCKED');
 assert.equal(verify(r).provisionalState,'INCONCLUSIVE');
 assert.equal(verify(r).approvalAuthorized,false);
});
test('signed synthetic review evidence cannot bypass nonce replay authority',()=>{
 const r=stage('pull_request_target:');
 assert.throws(()=>verify(r,new Set([nonce])),/REPLAY_DETECTED/);
});
