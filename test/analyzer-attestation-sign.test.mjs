import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { canonicalJson } from '../src/canonical.mjs';
import { signAnalyzerAttestationFixture as make } from
  '../candidate/analyzer-attestation-sign.mjs';

const pair=generateKeyPairSync('ed25519');
const bad=generateKeyPairSync('ed25519');
const rsa=generateKeyPairSync('rsa',{modulusLength:2048});
const sha=b=>createHash('sha256').update(b).digest('hex');
const pk=pair.privateKey.export({type:'pkcs8',format:'pem'});
const fingerprint=sha(pair.publicKey.export({type:'spki',format:'der'}));
const target={
  repository:'deenkids7-dev/deenkids',repository_id:1282086207,
  pr_number:898,head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),
  diff_sha256:sha('synthetic diff')
};
const runId='synthetic-analyzer-001';
const reportBytes=Buffer.from(canonicalJson({
  schema:'devfactory.reviewer-b.findings.v1',run_id:runId,
  summary:'Synthetic static report only - no independent reviewer',
  findings:[]
}));
const args=(overrides={})=>({
  reportBytes,changedPaths:['src/example.mjs'],target,runId,
  issuer:'isolated-fixture',reviewerId:'reviewer-fixture',keyId:'fake-key',
  ed25519PrivateKeyPem:pk,pinnedEd25519SpkiSha256:fingerprint,
  nonce:'11111111-2222-4333-8444-555555555555',
  issuedAt:'2026-10-10T12:00:00Z',
  expiresAt:'2026-10-10T12:10:00Z',
  now:Date.parse('2026-10-10T12:00:30Z'),
  ...overrides
});
test('signed no-findings fixture is BLOCKED, not approved',()=>{
  const result=make(args());
  assert.equal(result.signedDisposition,'BLOCKED');
  assert.equal(result.approvalAuthorized,false);
  assert.equal(result.reviewerIndependenceVerified,false);
  const env=JSON.parse(result.envelopeBytes.toString());
  assert.equal(env.payload.analysis.disposition,'BLOCKED');
  assert.equal(env.payload.target.repository,'deenkids7-dev/deenkids');
});
test('synthetic high-severity finding may sign FAIL but not approval',()=>{
  const report=Buffer.from(canonicalJson({
    schema:'devfactory.reviewer-b.findings.v1',run_id:runId,
    summary:'Synthetic blocker',
    findings:[{
      fingerprint:'f'.repeat(64),severity:'high',path:'src/example.mjs',
      line:1,message:'Synthetic vulnerability',evidence:'Fixture only'
    }]
  }));
  const r=make(args({reportBytes:report}));
  assert.equal(r.signedDisposition,'FAIL');
  assert.equal(r.approvalAuthorized,false);
});
test('wrong signing key fingerprint rejected before producing a report',()=>{
  for(const modified of [
    {pinnedEd25519SpkiSha256:'0'.repeat(64)},
    {ed25519PrivateKeyPem:bad.privateKey.export({type:'pkcs8',format:'pem'})}
  ])assert.throws(()=>make(args(modified)),
    /ANALYZER_SIGNER_KEY_FINGERPRINT_MISMATCH/);
});
test('RSA key cannot substitute Ed25519 analyzer signing identity',()=>{
  assert.throws(()=>make(args({
    ed25519PrivateKeyPem:rsa.privateKey.export({type:'pkcs8',format:'pem'})
  })),/ANALYZER_SIGNER_WRONG_PRIVATE_KEY/);
});
test('signed run ID must match findings report',()=>{
  assert.throws(()=>make(args({runId:'different-run-001'})),
    /ANALYZER_SIGNER_RUN_ID_MISMATCH/);
});
test('wrong target repository or HEAD always blocked',()=>{
  assert.throws(()=>make(args({
    target:{...target,repository:'other/repo'}
  })),/ANALYZER_SIGNER_TARGET_UNVERIFIED/);
  assert.throws(()=>make(args({
    target:{...target,head_sha:'oops'}
  })),/ANALYZER_SIGNER_TARGET_UNVERIFIED/);
});
test('expired attestation cannot be signed into current authority',()=>{
  assert.throws(()=>make(args({
    now:Date.parse('2026-10-10T12:11:00Z')
  })),/ANALYZER_SIGNER_INPUT_INVALID/);
});
test('tampered unsigned report cannot be signed',()=>{
  assert.throws(()=>make(args({
    reportBytes:Buffer.from('noncanonical invalid')
  })),/REVIEW_INVALID_JSON/);
});
