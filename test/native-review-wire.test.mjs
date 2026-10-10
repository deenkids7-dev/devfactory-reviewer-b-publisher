import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { formatNativeReviewFixture, nativePayloadBytes } from '../src/native-review-wire.mjs';

const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const {privateKey:untrustedPrivate}=generateKeyPairSync('rsa',{modulusLength:2048});
const publicKeyPem=publicKey.export({format:'pem',type:'spki'});
const sha=value=>createHash('sha256').update(value).digest('hex');
const pinnedKeySha256=sha(publicKey.export({format:'der',type:'spki'}));
const reportText='Synthetic-only review fixture. No independent audit performed.';
function payload(changes={}) {
  return {
    app_bot_id:340237276,base_sha:'b'.repeat(40),
    completed_at:'2026-10-10T08:00:00Z',
    head_sha:'a'.repeat(40),installation_id:169674558,
    nonce:'c'.repeat(32),pr_number:898,provenance_ref:'fixture:synthetic-run-898',
    report_sha256:sha(reportText),repository:'deenkids7-dev/deenkids',
    reviewer_run_id:'fixture-run-898',verdict:'PASS',...changes
  };
}
function fixture(overrides={},signer=privateKey) {
  const p=payload(overrides);
  return {
    payload:p,reportText,
    signatureBase64Url:sign('sha256',nativePayloadBytes(p),signer).toString('base64url'),
    pinnedPublicKeyPem:publicKeyPem,pinnedKeySha256
  };
}
function reject(name,build,expected) {
  test(name,()=>assert.throws(()=>formatNativeReviewFixture(build()),
    e=>e.message===expected));
}
test('exact native RSA fixture structure but NEVER independent/authorized',()=>{
  const rendered=formatNativeReviewFixture(fixture());
  assert.equal(rendered.cryptographicIntegrityVerified,true);
  assert.equal(rendered.reviewIndependenceVerified,false);
  assert.equal(rendered.approvalAuthorized,false);
  assert.equal(rendered.publishEvent,null);
  assert.equal(rendered.dispositionClaimedBySigner,'PASS');
  const marker=rendered.reviewBody.match(/^<!-- devfactory-reviewer-b-native:v1:([A-Za-z0-9_-]+) -->\n/);
  assert.ok(marker);
  const encoded=JSON.parse(Buffer.from(marker[1],'base64url').toString('utf8'));
  assert.deepEqual(encoded.payload,payload());
  assert.equal(encoded.signature,fixture().signatureBase64Url);
  assert.equal(rendered.reviewBody.slice(marker[0].length),reportText);
});
test('FAIL wire also has no publication authority',()=>{
  const result=formatNativeReviewFixture(fixture({verdict:'FAIL'}));
  assert.equal(result.publishEvent,null);
  assert.equal(result.dispositionClaimedBySigner,'FAIL');
  assert.equal(result.approvalAuthorized,false);
});
reject('reject altered signed payload',()=>{
  const x=fixture();
  return {...x,payload:{...x.payload,head_sha:'f'.repeat(40)}};
},'NATIVE_BAD_RSA_SIGNATURE');
reject('reject malformed report digest',()=>{
  const x=fixture();
  return {...x,reportText:'tampered report'};
},'NATIVE_REPORT_MISMATCH');
reject('reject wrong app installation',()=>{
  const x=fixture({installation_id:999});
  return x;
},'NATIVE_INVALID_PAYLOAD');
reject('reject extra signed payload field',()=>{
  const x=fixture();
  return {...x,payload:{...x.payload,secret_override:true}};
},'NATIVE_INVALID_FIELDS');
reject('reject changed required repository',()=>{
  const x=fixture({repository:'other/repo'});
  return x;
},'NATIVE_INVALID_PAYLOAD');
reject('reject untrusted signing key',()=>fixture({},untrustedPrivate),
  'NATIVE_BAD_RSA_SIGNATURE');
reject('reject fingerprint mismatch',()=>{
  const x=fixture();
  return {...x,pinnedKeySha256:'0'.repeat(64)};
},'NATIVE_UNTRUSTED_KEY');
reject('reject uncanonical base64url signature',()=>{
  const x=fixture();
  return {...x,signatureBase64Url:x.signatureBase64Url+'='};
},'NATIVE_INVALID_SIGNATURE_ENCODING');
reject('reject invalid nonce',()=>fixture({nonce:'short'}),
  'NATIVE_INVALID_PAYLOAD');
reject('reject nonzero invalid timestamp',()=>fixture({completed_at:'not-a-date'}),
  'NATIVE_INVALID_PAYLOAD');
reject('reject unreviewed state field',()=>fixture({verdict:'BLOCKED'}),
  'NATIVE_INVALID_PAYLOAD');

for(const bad of ['1','Oct 10 2026','2026-10-10T08:00:00+00:00','2026-10-10T08:00:00.000Z','2026-02-30T08:00:00Z', '2026-10-10T08:00:00Z'.padEnd(20000,'!')]){
  reject('reject noncanonical native UTC timestamp '+bad.slice(0,24),()=>fixture({completed_at:bad}),
    'NATIVE_INVALID_PAYLOAD');
}
test('native payload signing bytes use deterministic ASCII key ordering',()=>{
  const obj=payload();
  const encoded=nativePayloadBytes(obj).toString('utf8');
  assert.deepEqual(Object.keys(JSON.parse(encoded)),Object.keys(obj).sort());
});
