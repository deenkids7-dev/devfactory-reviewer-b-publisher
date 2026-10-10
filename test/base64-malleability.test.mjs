import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJson } from '../src/canonical.mjs';
import { verifyAttestation } from '../src/verify-attestation.mjs';

test('rejects malleable base64 pad bits even when signature bytes match', () => {
  const pair = generateKeyPairSync('ed25519');
  const reportBytes = Buffer.from('Synthetic fixture only');
  const digest = data => createHash('sha256').update(data).digest('hex');
  const target = {
    repository: 'deenkids7-dev/deenkids', repository_id: 1282086207,
    pr_number: 898, head_sha: 'a'.repeat(40), base_sha: 'b'.repeat(40),
    diff_sha256: digest('test diff')
  };
  const payload = {
    schema:'devfactory.reviewer-b.attestation.v1', issuer:'fixture-isolated',
    review_id:'fixture-01', nonce:'11111111-2222-4333-8444-555555555555',
    issued_at:'2026-10-10T08:00:00Z', expires_at:'2026-10-10T08:10:00Z',
    target, analysis: {
      reviewer_id:'fixture-reviewer', disposition:'PASS',
      report_sha256:digest(reportBytes)
    }
  };
  const signature = sign(null, Buffer.from(canonicalJson(payload)), pair.privateKey).toString('base64');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const lastIndex = signature.length - 3;
  const index = alphabet.indexOf(signature[lastIndex]);
  assert.equal(index % 16, 0);
  const altered = signature.slice(0,lastIndex) + alphabet[index ^ 1] + signature.slice(lastIndex+1);
  assert.notEqual(altered, signature);
  assert.ok(Buffer.from(altered,'base64').equals(Buffer.from(signature,'base64')));
  const trustedKeys = new Map([['fixture', {
    publicKeyPem:pair.publicKey.export({format:'pem',type:'spki'}),
    issuer:'fixture-isolated', reviewerId:'fixture-reviewer'
  }]]);
  const context = {
    reportBytes, trustedKeys, trustedTarget:target,
    seenReviewIds:new Set(), seenNonces:new Set(),
    now:Date.parse('2026-10-10T08:00:30Z')
  };
  const result = verifyAttestation({
    envelope:{payload,signature:{algorithm:'Ed25519',key_id:'fixture',value:signature}},
    ...context
  });
  assert.equal(result.approvalAuthorized,false);
  assert.throws(()=>verifyAttestation({
    envelope:{payload,signature:{algorithm:'Ed25519',key_id:'fixture',value:altered}},
    ...context
  }), e=>e.message==='MALFORMED_SIGNATURE');
});
