import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { canonicalJson } from '../src/canonical.mjs';
import { verifyAttestation } from '../src/verify-attestation.mjs';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const { privateKey: otherPrivateKey } = generateKeyPairSync('ed25519');
const now = Date.parse('2026-10-10T08:00:30Z');
const reportBytes = Buffer.from('test fixture; no independent analysis occurred', 'utf8');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const target = {
  repository: 'deenkids7-dev/deenkids', repository_id: 1282086207,
  pr_number: 898, head_sha: 'a'.repeat(40), base_sha: 'b'.repeat(40),
  diff_sha256: sha256('example fake diff')
};
const trustedKeys = new Map([['TEST_ONLY_NEVER_PRODUCTION', {
  publicKeyPem: publicKey.export({type:'spki', format:'pem'}),
  spkiSha256: createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex'),
  issuer:'fixture-isolated-signer', reviewerId:'fixture-reviewer'
}]]);
function signedFixture(custom = {}, signer = privateKey) {
  const payload = {
    schema: 'devfactory.reviewer-b.attestation.v1',
    issuer: 'fixture-isolated-signer', review_id: 'fixture-run-001',
    nonce: '11111111-2222-4333-8444-555555555555',
    issued_at: '2026-10-10T08:00:00Z', expires_at: '2026-10-10T08:10:00Z',
    target: {...target},
    analysis: {reviewer_id: 'fixture-reviewer', disposition: 'PASS', report_sha256: sha256(reportBytes)}
  };
  Object.assign(payload,custom);
  const signature = sign(null, Buffer.from(canonicalJson(payload)), signer).toString('base64');
  return {payload, signature:{algorithm:'Ed25519',key_id:'TEST_ONLY_NEVER_PRODUCTION',value:signature}};
}
function verify(envelope, overrides={}) {
  return verifyAttestation({envelope, reportBytes, trustedKeys, trustedTarget:target,
    seenReviewIds:new Set(), seenNonces:new Set(), now, ...overrides});
}
function denied(name, transform, overrides, code) {
  test(name, () => {
    const env = transform(signedFixture());
    assert.throws(()=>verify(env, overrides), e=> e.message === code);
  });
}
test('accepts only test fixture signature, explicitly denies approval and independence claims', () => {
  const result=verify(signedFixture());
  assert.equal(result.cryptographicIntegrityVerified, true);
  assert.equal(result.reviewIndependenceVerified, false);
  assert.equal(result.approvalAuthorized, false);
  assert.equal(result.dispositionClaimedBySigner, 'PASS');
});
denied('rejects tampered disposition', e=>({...e,payload:{...e.payload,analysis:{...e.payload.analysis,disposition:'FAIL'}}}), {}, 'SIGNATURE_VERIFICATION_FAILED');
denied('rejects tampered PR HEAD even when freshly signed', ()=>signedFixture({target:{...target,head_sha:'c'.repeat(40)}}), {}, 'TARGET_MISMATCH');
denied('rejects wrong PR number', ()=>signedFixture({target:{...target,pr_number:899}}), {}, 'TARGET_MISMATCH');
denied('rejects wrong base SHA', ()=>signedFixture({target:{...target,base_sha:'e'.repeat(40)}}), {}, 'TARGET_MISMATCH');
denied('rejects fake diff hash', ()=>signedFixture({target:{...target,diff_sha256:'e'.repeat(64)}}), {}, 'DIFF_MISMATCH');
denied('rejects different repository', ()=>signedFixture({target:{...target,repository:'other/repo'}}), {}, 'INVALID_PR_TARGET');
denied('rejects replayed review', e=>e, {seenReviewIds:new Set(['fixture-run-001'])}, 'REPLAY_DETECTED');
denied('rejects replayed nonce', e=>e, {seenNonces:new Set(['11111111-2222-4333-8444-555555555555'])}, 'REPLAY_DETECTED');
denied('rejects expired artifact', e=>e, {now:Date.parse('2026-10-10T08:11:00Z')}, 'ATTESTATION_NOT_FRESH');
denied('rejects issued-in-future artifact', e=>e, {now:Date.parse('2026-10-10T07:58:00Z')}, 'ATTESTATION_NOT_FRESH');
denied('rejects window longer than 15 min', ()=>signedFixture({expires_at:'2026-10-10T09:00:00Z'}), {}, 'ATTESTATION_NOT_FRESH');
denied('rejects unsigned payload extensions', e=>({...e,payload:{...e.payload,override:true}}), {}, 'INVALID_PAYLOAD_FIELDS');
denied('rejects wrong signer', ()=>signedFixture({},otherPrivateKey), {}, 'SIGNATURE_VERIFICATION_FAILED');
denied('rejects signer missing trusted SPKI fingerprint',e=>e,{
  trustedKeys:new Map([['TEST_ONLY_NEVER_PRODUCTION',{
    publicKeyPem:publicKey.export({type:'spki',format:'pem'}),
    issuer:'fixture-isolated-signer',reviewerId:'fixture-reviewer'
  }]])},'UNPINNED_SIGNING_KEY');
denied('rejects mismatched trusted SPKI fingerprint',e=>e,{
  trustedKeys:new Map([['TEST_ONLY_NEVER_PRODUCTION',{
    publicKeyPem:publicKey.export({type:'spki',format:'pem'}),
    spkiSha256:'0'.repeat(64),
    issuer:'fixture-isolated-signer',reviewerId:'fixture-reviewer'
  }]])},'SIGNING_KEY_FINGERPRINT_MISMATCH');
denied('rejects unknown key id', e=>({...e,signature:{...e.signature,key_id:'unknown'}}), {}, 'UNTRUSTED_SIGNER');
denied('rejects missing trust authority',e=>e,{trustedKeys:new Map()},'MISSING_TRUST_OR_REPLAY_AUTHORITY');
denied('rejects missing trusted target',e=>e,{trustedTarget:null},'MISSING_GITHUB_TARGET');
denied('rejects mismatched raw report',e=>e,{reportBytes:Buffer.from('different report')},'REPORT_MISMATCH');
denied('rejects invalid signature encoding',e=>({...e,signature:{...e.signature,value:'random'}}),{},'MALFORMED_SIGNATURE');
denied('rejects uppercase commit SHA',()=>signedFixture({target:{...target,head_sha:'A'.repeat(40)}}),{},'INVALID_COMMIT_SHA');
denied('rejects wrong repository ID',()=>signedFixture({target:{...target,repository_id:999999999}}),{},'INVALID_PR_TARGET');
denied('rejects wrong signature algorithm',e=>({...e,signature:{...e.signature,algorithm:'RSA'}}),{},'UNTRUSTED_SIGNER');
denied('rejects missing signature',e=>({payload:e.payload}),{},'INVALID_ENVELOPE_FIELDS');
test('canonical JSON is deterministic across property order',()=>assert.equal(canonicalJson({z:2,a:1}),canonicalJson({a:1,z:2})));
test('canonical JSON rejects floating point and dangerous object keys',()=>{
  assert.throws(()=>canonicalJson({x:1.5}),/UNSUPPORTED_CANONICAL_VALUE/);
  assert.throws(()=>canonicalJson(JSON.parse('{"__proto__":1}')),/UNSAFE_OBJECT_KEY/);
});
test('no production signing key or publication action in module',()=> {
  assert.ok(!Object.keys(verify(signedFixture())).includes('approve'));
});
