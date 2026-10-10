import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { runFailOnlyStaticDiffAudit } from '../candidate/fail-only-static-audit.mjs';
import { prepareBoundedSemanticReview }
  from '../candidate/semantic-review-request.mjs';
import { prepareDeepSeekCandidate, validateDeepSeekCandidateCompletion }
  from '../candidate/deepseek-review-contract.mjs';
import { combineReviewerFindings } from '../candidate/combine-findings.mjs';
import { signAnalyzerAttestationFixture }
  from '../candidate/analyzer-attestation-sign.mjs';
import { verifyReviewEvidence } from '../src/evidence-preflight.mjs';

const runId='fixture-review-898';
const path='.github/workflows/guard.yml';
const sha256=data=>createHash('sha256').update(data).digest('hex');
const privateKeyPair=generateKeyPairSync('ed25519');
const privatePem=privateKeyPair.privateKey.export({format:'pem',type:'pkcs8'});
const publicPem=privateKeyPair.publicKey.export({format:'pem',type:'spki'});
const spkiDigest=sha256(privateKeyPair.publicKey.export({format:'der',type:'spki'}));
const now=Date.parse('2026-10-10T08:02:00Z');
function diffBytes(isDangerous=false) {
  const added=isDangerous?'pull_request_target:':'pull_request:';
  return Buffer.from('diff --git a/'+path+' b/'+path+'\n'+
    'index 1234567..7654321 100644\n--- a/'+path+'\n+++ b/'+path+'\n'+
    '@@ -1 +1 @@\n-name: original\n+'+added+'\n');
}
function staged(isDangerous=false) {
  const diff=diffBytes(isDangerous);
  const target={
    repository:'deenkids7-dev/deenkids',repository_id:1282086207,
    pr_number:898,head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),
    diff_sha256:sha256(diff)
  };
  const staticResult=runFailOnlyStaticDiffAudit({diffBytes:diff,runId});
  const plan=prepareBoundedSemanticReview({snapshot:target,rawDiffBytes:diff});
  const modelCandidate=prepareDeepSeekCandidate({plan,inputTokenCeiling:10000});
  // Simulated response only; no network call or real reviewer identity.
  const semantic=validateDeepSeekCandidateCompletion({
    response:{
      model:'deepseek-flash',
      choices:[{index:0,finish_reason:'stop',
        message:{role:'assistant',content:JSON.stringify({
          summary:'Synthetic LLM found no additional issues',findings:[]
        })}}],
      usage:{prompt_tokens:6000,completion_tokens:256}
    },
    expectedModel:'deepseek-flash',runId,
    trustedChangedPaths:plan.changedPaths,
    observedInputTokenCeiling:10000,observedOutputTokenCeiling:2048
  });
  const combined=combineReviewerFindings({
    staticReportBytes:staticResult.reportBytes,
    semanticReportBytes:semantic.privateCanonicalReportBytes,
    changedPaths:plan.changedPaths
  });
  const signed=signAnalyzerAttestationFixture({
    reportBytes:combined.reportBytes,changedPaths:plan.changedPaths,
    target,runId,issuer:'synthetic-independent',
    reviewerId:'fixture-reviewer',keyId:'fixture-ed25519',
    ed25519PrivateKeyPem:privatePem,
    pinnedEd25519SpkiSha256:spkiDigest,
    nonce:'11111111-2222-4333-8444-555555555555',
    issuedAt:'2026-10-10T08:00:00Z',
    expiresAt:'2026-10-10T08:10:00Z',now
  });
  return {target,staticResult,modelCandidate,semantic,combined,signed,paths:plan.changedPaths};
}
function validate(d) {
  return verifyReviewEvidence({
    envelopeBytes:d.signed.envelopeBytes,
    reportBytes:d.combined.reportBytes,
    trustedKeys:new Map([['fixture-ed25519',{
      issuer:'synthetic-independent',reviewerId:'fixture-reviewer',
      publicKeyPem:publicPem,spkiSha256:spkiDigest
    }]]),
    trustedTarget:d.target,trustedChangedPaths:d.paths,
    seenReviewIds:new Set(),seenNonces:new Set(),now
  });
}
test('offline security blocker survives clean model output and signed attestation',()=>{
  const d=staged(true);
  assert.equal(d.staticResult.blockingFindings,1);
  assert.equal(d.combined.blockingFindings,1);
  assert.equal(d.signed.signedDisposition,'FAIL');
  assert.equal(d.modelCandidate.requestAuthorized,false);
  assert.equal(d.semantic.approvalAuthorized,false);
  assert.equal(d.semantic.provisionalState,'INCONCLUSIVE');

  const result=validate(d);
  assert.equal(result.provisionalState,'FAIL');
  assert.equal(result.signatureVerified,true);
  assert.equal(result.approvalAuthorized,false);
  assert.equal(result.independenceVerified,false);
  assert.ok(!d.combined.reportBytes.toString().includes('pull_request_target:'));
});
test('offline clean diff stays INCONCLUSIVE and signed BLOCKED, never PASS',()=>{
  const d=staged(false);
  assert.equal(d.staticResult.blockingFindings,0);
  assert.equal(d.combined.blockingFindings,0);
  assert.equal(d.signed.signedDisposition,'BLOCKED');
  const r=validate(d);
  assert.equal(r.provisionalState,'INCONCLUSIVE');
  assert.equal(r.approvalAuthorized,false);
});
test('integrated signature cannot be replayed',()=>{
  const d=staged(true);
  const options={
    envelopeBytes:d.signed.envelopeBytes,
    reportBytes:d.combined.reportBytes,
    trustedKeys:new Map([['fixture-ed25519',{
      issuer:'synthetic-independent',reviewerId:'fixture-reviewer',
      publicKeyPem:publicPem,spkiSha256:spkiDigest
    }]]),
    trustedTarget:d.target,trustedChangedPaths:d.paths,
    seenReviewIds:new Set(),seenNonces:new Set([
      '11111111-2222-4333-8444-555555555555'
    ]),now
  };
  assert.throws(()=>verifyReviewEvidence(options),e=>e.message==='REPLAY_DETECTED');
});
