import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { signNativeMarkerOnly } from '../candidate/native-marker-sign.mjs';

const appKey=generateKeyPairSync('rsa',{modulusLength:2048});
const signer=generateKeyPairSync('rsa',{modulusLength:2048});
const sha=value=>createHash('sha256').update(value).digest('hex');
const spki=k=>sha(k.export({type:'spki',format:'der'}));
const appFingerprint=spki(appKey.publicKey);
const nativeFingerprint=spki(signer.publicKey);
const nativePem=signer.privateKey.export({type:'pkcs8',format:'pem'});
const reportText='SYNTHETIC FIXTURE ONLY: No review occurred';
const payload=()=>({
  app_bot_id:340237276,base_sha:'b'.repeat(40),
  completed_at:'2026-10-10T12:20:00Z',
  head_sha:'a'.repeat(40),installation_id:169674558,
  nonce:'f'.repeat(32),pr_number:898,provenance_ref:'synthetic:fixture-898',
  report_sha256:sha(reportText),repository:'deenkids7-dev/deenkids',
  reviewer_run_id:'synthetic-run-898',verdict:'FAIL'
});
const args=(overrides={})=>({
  payload:payload(),reportText,nativeSignerPrivateKeyPem:nativePem,
  pinnedSignerSpkiSha256:nativeFingerprint,
  pinnedAppSpkiSha256:appFingerprint,...overrides
});

test('separate RSA marker signature never publishes a review',()=>{
  const result=signNativeMarkerOnly(args());
  assert.equal(result.publishEvent,null);
  assert.equal(result.approvalAuthorized,false);
  assert.equal(result.reviewIndependenceVerified,false);
  assert.equal(result.signerSpkiSha256,nativeFingerprint);
  assert.equal(result.dispositionClaimedBySigner,'FAIL');
  assert.match(result.reviewBody,/^<!-- devfactory-reviewer-b-native:v1:/);
  assert.ok(!result.reviewBody.includes('PRIVATE KEY'));
});
test('signer cannot reuse GitHub App private signing identity',()=>{
  const sameAsApp=signer.privateKey.export({type:'pkcs8',format:'pem'});
  assert.throws(()=>signNativeMarkerOnly(args({
    pinnedAppSpkiSha256:nativeFingerprint,
    nativeSignerPrivateKeyPem:sameAsApp
  })),/NATIVE_SIGNER_REUSES_APP_JWT_KEY/);
});
test('an unpinned or changed native RSA key is forbidden',()=>{
  for(const fp of [null,'0'.repeat(64),'BAD']){
    assert.throws(()=>signNativeMarkerOnly(args({
      pinnedSignerSpkiSha256:fp
    })),/NATIVE_SIGNER_(?:UNPROVISIONED|FINGERPRINT_MISMATCH)/);
  }
});
test('invalid and non-RSA keys are rejected',()=>{
  const ed=generateKeyPairSync('ed25519');
  for(const value of [
    '',null,
    ed.privateKey.export({type:'pkcs8',format:'pem'}),
    'invalid'.repeat(40)
  ]){
    assert.throws(()=>signNativeMarkerOnly(args({
      nativeSignerPrivateKeyPem:value
    })),/NATIVE_SIGNER_(?:UNPROVISIONED|INVALID_PRIVATE_KEY|KEY_DENIED)/);
  }
});
test('no signer may forge invalid native review payload schema',()=>{
  const p=payload();p.installation_id=99;
  assert.throws(()=>signNativeMarkerOnly(args({payload:p})),
    /NATIVE_INVALID_PAYLOAD/);
});
test('native RSA signature binds exact report bytes',()=>{
  assert.throws(()=>signNativeMarkerOnly(args({
    reportText:'changed text'
  })),/NATIVE_REPORT_MISMATCH/);
});

test('PASS is unconditionally refused before native RSA signing',()=>{
  assert.throws(()=>signNativeMarkerOnly(args({payload:{...payload(),verdict:'PASS'}})),
    /NATIVE_SIGNER_PASS_NOT_AUTHORIZED/);
});

test('RSA signer never accidentally serializes private GitHub review body',()=>{
 const secret='SYNTHETIC_PRIVATE_REVIEW_TEXT_SHOULD_NOT_LOG';
 const p=payload();
 p.report_sha256=sha(secret);
 const result=signNativeMarkerOnly(args({payload:p,reportText:secret}));
 assert.ok(result.reviewBody.includes(secret));
 for(const raw of [JSON.stringify(result),JSON.stringify({...result}),inspect(result)])
  assert.ok(!raw.includes(secret));
 assert.equal(Object.keys(result).includes('reviewBody'),false);
 assert.equal(result.publishEvent,null);
});
test('wrong-type and weak RSA native signer keys preserve precise type denial',()=>{
  const ed=generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'});
  const weak=generateKeyPairSync('rsa',{modulusLength:1024}).privateKey.export({type:'pkcs8',format:'pem'});
  for(const nativeSignerPrivateKeyPem of [ed,weak]){
    assert.throws(()=>signNativeMarkerOnly(args({nativeSignerPrivateKeyPem})),
      e=>e.message==='NATIVE_SIGNER_KEY_DENIED');
  }
  assert.throws(()=>signNativeMarkerOnly(args({nativeSignerPrivateKeyPem:'bad key'.repeat(20)})),
    e=>e.message==='NATIVE_SIGNER_INVALID_PRIVATE_KEY');
});
