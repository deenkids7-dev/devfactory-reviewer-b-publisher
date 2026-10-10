import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJson } from '../src/canonical.mjs';
import { verifyReviewEvidence } from '../src/evidence-preflight.mjs';

const keys=generateKeyPairSync('ed25519');
const digest=data=>createHash('sha256').update(data).digest('hex');
const changedPaths=['src/synthetic.mjs'];
const trustedTarget={
  repository:'deenkids7-dev/deenkids',repository_id:1282086207,
  pr_number:898,head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),
  diff_sha256:digest('synthetic-only fake diff')
};
const signerKeys=new Map([['TEST_ONLY',{issuer:'fixture-isolated',
  reviewerId:'fixture-reviewer',
  publicKeyPem:keys.publicKey.export({type:'spki',format:'pem'})
}]]);
const now=Date.parse('2026-10-10T08:00:30Z');
const finding=()=>({
  fingerprint:'c'.repeat(64),severity:'high',
  path:'src/synthetic.mjs',line:12,
  message:'Synthetic blocker',evidence:'Fixture only'
});
function fixture({findings=[],disposition='PASS',reportRun='fixture-run-001',
    signedRun=reportRun,modifiedTarget={}}={}) {
  const reportBytes=Buffer.from(JSON.stringify({
    schema:'devfactory.reviewer-b.findings.v1',
    run_id:reportRun, summary:'Synthetic review; no independent analysis',
    findings
  }));
  const payload={
    schema:'devfactory.reviewer-b.attestation.v1',issuer:'fixture-isolated',
    review_id:signedRun,nonce:'11111111-2222-4333-8444-555555555555',
    issued_at:'2026-10-10T08:00:00Z',expires_at:'2026-10-10T08:10:00Z',
    target:{...trustedTarget,...modifiedTarget},
    analysis:{reviewer_id:'fixture-reviewer',disposition,report_sha256:digest(reportBytes)}
  };
  const signature=sign(null,Buffer.from(canonicalJson(payload)),keys.privateKey).toString('base64');
  return { envelopeBytes:Buffer.from(canonicalJson({
      payload,signature:{algorithm:'Ed25519',key_id:'TEST_ONLY',value:signature}
    })),
    reportBytes,trustedKeys:signerKeys,trustedTarget,
    trustedChangedPaths:changedPaths,
    seenReviewIds:new Set(),seenNonces:new Set(),now
  };
}
test('even signed no-findings PASS is INCONCLUSIVE and never approves',()=>{
  const r=verifyReviewEvidence(fixture());
  assert.equal(r.signatureVerified,true);
  assert.equal(r.provisionalState,'INCONCLUSIVE');
  assert.equal(r.approvalAuthorized,false);
  assert.equal(r.independenceVerified,false);
});
test('signed high severity FAIL remains provisional FAIL but cannot publish',()=>{
  const r=verifyReviewEvidence(fixture({findings:[finding()],disposition:'FAIL'}));
  assert.equal(r.provisionalState,'FAIL');
  assert.equal(r.blockingFindingCount,1);
  assert.equal(r.approvalAuthorized,false);
});
test('signed PASS contradicted by blocker is rejected',()=>{
  assert.throws(()=>verifyReviewEvidence(fixture({
    findings:[finding()],disposition:'PASS'
  })),e=>e.message==='SIGNED_PASS_CONTRADICTS_BLOCKING_FINDINGS');
});
test('signed FAIL without blocker is rejected',()=>{
  assert.throws(()=>verifyReviewEvidence(fixture({disposition:'FAIL'})),
    e=>e.message==='SIGNED_FAIL_MISSING_BLOCKER_EVIDENCE');
});
test('signed run ID must match report run ID',()=>{
  assert.throws(()=>verifyReviewEvidence(fixture({
    reportRun:'fixture-run-001',signedRun:'fixture-run-002'
  })),e=>e.message==='ANALYSIS_RUN_ID_MISMATCH');
});
test('signed HEAD cannot diverge from trusted GitHub target',()=>{
  assert.throws(()=>verifyReviewEvidence(fixture({
    modifiedTarget:{head_sha:'c'.repeat(40)}
  })),e=>e.message==='TARGET_MISMATCH');
});
test('reports outside trusted changed-file scope are blocked',()=>{
  const f={...finding(),path:'not-changed/file.mjs'};
  assert.throws(()=>verifyReviewEvidence(fixture({
    findings:[f],disposition:'FAIL'
  })),e=>e.message==='REVIEW_FINDING_INVALID');
});
test('report byte mutation is detected before findings evaluation',()=>{
  const f=fixture();
  const malformed={...f,reportBytes:Buffer.from('{}')};
  assert.throws(()=>verifyReviewEvidence(malformed),
    e=>e.message==='REPORT_MISMATCH');
});
test('replayed nonce remains forbidden in integrated preflight',()=>{
  const f=fixture();
  assert.throws(()=>verifyReviewEvidence({
    ...f,seenNonces:new Set(['11111111-2222-4333-8444-555555555555'])
  }),e=>e.message==='REPLAY_DETECTED');
});
