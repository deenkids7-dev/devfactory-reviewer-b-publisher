import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJson } from '../src/canonical.mjs';
import { parseCanonicalEnvelope, verifySerializedAttestation } from '../src/strict-envelope.mjs';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const reportBytes = Buffer.from('Fixture only: NO review was performed');
const sha256 = value => createHash('sha256').update(value).digest('hex');
const now = Date.parse('2026-10-10T08:00:30Z');
const trustedTarget = Object.freeze({
  repository: 'deenkids7-dev/deenkids', repository_id: 1282086207,
  pr_number: 898, head_sha: 'a'.repeat(40), base_sha: 'b'.repeat(40),
  diff_sha256: sha256('synthetic fake diff')
});
const trustedKeys = new Map([['FIXTURE_ONLY', {
  publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }),
  issuer: 'synthetic-fixture', reviewerId: 'synthetic-reviewer'
}]]);
function signed() {
  const payload = {
    schema: 'devfactory.reviewer-b.attestation.v1', issuer: 'synthetic-fixture',
    review_id: 'fixture-0001', nonce: '11111111-2222-4333-8444-555555555555',
    issued_at: '2026-10-10T08:00:00Z', expires_at: '2026-10-10T08:10:00Z',
    target: trustedTarget, analysis: {
      reviewer_id: 'synthetic-reviewer', disposition: 'PASS',
      report_sha256: sha256(reportBytes)
    }
  };
  return { payload, signature: {
    algorithm: 'Ed25519', key_id: 'FIXTURE_ONLY',
    value: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString('base64')
  }};
}
const bytes = () => Buffer.from(canonicalJson(signed()), 'utf8');
function verify(envelopeBytes, extra={}) {
  return verifySerializedAttestation({
    envelopeBytes, reportBytes, trustedKeys, trustedTarget,
    seenReviewIds: new Set(), seenNonces: new Set(), now, ...extra
  });
}
function rejects(name, fixture, errorCode) {
  test(name, () => assert.throws(() => parseCanonicalEnvelope(fixture()),
    e => e.message === errorCode));
}

test('accepts exact canonical signed bytes but refuses approval', () => {
  const verified = verify(bytes());
  assert.equal(verified.cryptographicIntegrityVerified, true);
  assert.equal(verified.reviewIndependenceVerified, false);
  assert.equal(verified.approvalAuthorized, false);
});
rejects('rejects whitespace changes', () => Buffer.from(bytes().toString()+'\n'),
  'NONCANONICAL_ATTESTATION');
rejects('rejects unsorted object keys', () => Buffer.from(JSON.stringify(signed())),
  'NONCANONICAL_ATTESTATION');
rejects('rejects JSON duplicate properties', () => {
  const doc = bytes().toString();
  return Buffer.from(doc.replace('{"payload":', '{"payload":null,"payload":'));
}, 'NONCANONICAL_ATTESTATION');
rejects('rejects malformed UTF8', () => Buffer.from([0xff, 0xfe, 0xfd]), 'INVALID_UTF8');
rejects('rejects oversized attestation', () => Buffer.alloc(65537, 0x20),
  'INVALID_ATTESTATION_SIZE');
rejects('rejects dangerous __proto__ key', () =>
  Buffer.from('{"__proto__":1}'), 'INVALID_ATTESTATION_SCHEMA_ENCODING');
rejects('rejects broken JSON', () => Buffer.from('{'), 'INVALID_ATTESTATION_SIZE');

test('rejects oversized raw report', () => assert.throws(() => verify(bytes(), {
  reportBytes: Buffer.alloc(2*1024*1024+1)
}), e => e.message === 'INVALID_REPORT_SIZE'));
test('rejects changed report bytes even with valid signature', () =>
  assert.throws(() => verify(bytes(), { reportBytes: Buffer.from('changed report') }),
    e => e.message === 'REPORT_MISMATCH'));
test('rejects modified signed payload on canonical transport', () => {
  const env = signed();
  env.payload.analysis.disposition = 'FAIL';
  assert.throws(() => verify(Buffer.from(canonicalJson(env))),
    e => e.message === 'SIGNATURE_VERIFICATION_FAILED');
});
test('rejects replay even on valid canonical transport', () =>
  assert.throws(() => verify(bytes(), { seenNonces: new Set([
    '11111111-2222-4333-8444-555555555555'
  ]) }), e => e.message === 'REPLAY_DETECTED'));
