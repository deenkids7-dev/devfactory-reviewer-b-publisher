import { createHash, createPublicKey, verify as verifySignature, timingSafeEqual } from 'node:crypto';
import { canonicalJson } from './canonical.mjs';

const SCHEMA = 'devfactory.reviewer-b.attestation.v1';
const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const IDENT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ISO_UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function reject(code) { throw new Error(code); }
function exactKeys(object, keys, code) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) reject(code);
  const actual = Object.keys(object).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) reject(code);
}
function sameHash(expected, actual, code) {
  if (typeof expected !== 'string' || typeof actual !== 'string' || !HEX64.test(expected) || !HEX64.test(actual)) reject(code);
  if (!timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(actual, 'hex'))) reject(code);
}
function parseUtc(iso, code) {
  if (typeof iso !== 'string' || !ISO_UTC.test(iso)) reject(code);
  const time = Date.parse(iso);
  if (!Number.isFinite(time) || new Date(time).toISOString().replace('.000Z','Z') !== iso) reject(code);
  return time;
}

/**
 * NO network access, NO GitHub write, NO approval.
 *
 * trustedTarget MUST be obtained independently by an authenticated fetch of the
 * exact current PR HEAD/BASE and exact diff bytes, never copied from envelope.
 * trustedKeys MUST contain pinned reviewer identities obtained independently,
 * never supplied by an untrusted PR, artifact or signed envelope.
 * seenReviewIds/seenNonces MUST be durable authoritative replay snapshots,
 * not caller-generated empty sets in any production path.
 *
 * The verifier only verifies cryptographic integrity of a claimed result.
 * It NEVER determines independent analysis or approval authority.
 */
export function verifyAttestation({ envelope, reportBytes, trustedKeys, trustedTarget,
  seenReviewIds, seenNonces, now = Date.now() }) {
  exactKeys(envelope, ['payload', 'signature'], 'INVALID_ENVELOPE_FIELDS');
  exactKeys(envelope.payload,
    ['schema', 'issuer', 'review_id', 'nonce', 'issued_at', 'expires_at', 'target', 'analysis'],
    'INVALID_PAYLOAD_FIELDS');
  exactKeys(envelope.payload.target,
    ['repository', 'repository_id', 'pr_number', 'head_sha', 'base_sha', 'diff_sha256'],
    'INVALID_TARGET_FIELDS');
  exactKeys(envelope.payload.analysis,
    ['reviewer_id', 'disposition', 'report_sha256'],
    'INVALID_ANALYSIS_FIELDS');
  exactKeys(envelope.signature,
    ['algorithm', 'key_id', 'value'],
    'INVALID_SIGNATURE_FIELDS');

  const p = envelope.payload;
  const s = envelope.signature;
  if (p.schema !== SCHEMA) reject('INVALID_SCHEMA');
  if (!IDENT.test(p.issuer) || !IDENT.test(p.review_id) || !IDENT.test(p.analysis.reviewer_id) || !UUID.test(p.nonce)) reject('INVALID_IDENTITY');
  if (!['PASS', 'FAIL', 'BLOCKED'].includes(p.analysis.disposition)) reject('INVALID_DISPOSITION');
  if (!HEX40.test(p.target.head_sha) || !HEX40.test(p.target.base_sha)) reject('INVALID_COMMIT_SHA');
  if (!HEX64.test(p.target.diff_sha256) || !HEX64.test(p.analysis.report_sha256)) reject('INVALID_DIGEST');
  if (p.target.repository !== 'deenkids7-dev/deenkids' ||
      p.target.repository_id !== 1282086207 ||
      !Number.isSafeInteger(p.target.pr_number) || p.target.pr_number < 1) reject('INVALID_PR_TARGET');
  if (typeof now !== 'number' || !Number.isFinite(now)) reject('INVALID_CLOCK');
  const issued = parseUtc(p.issued_at, 'INVALID_ISSUED_AT');
  const expires = parseUtc(p.expires_at, 'INVALID_EXPIRES_AT');
  if (issued > now + 60_000 || expires <= now || expires <= issued || expires - issued > 15 * 60_000) reject('ATTESTATION_NOT_FRESH');

  if (!(trustedKeys instanceof Map) || trustedKeys.size < 1 ||
      !(seenReviewIds instanceof Set) || !(seenNonces instanceof Set)) reject('MISSING_TRUST_OR_REPLAY_AUTHORITY');
  if (!trustedTarget || typeof trustedTarget !== 'object') reject('MISSING_GITHUB_TARGET');
  for (const field of ['repository', 'repository_id', 'pr_number', 'head_sha', 'base_sha']) {
    if (p.target[field] !== trustedTarget[field]) reject('TARGET_MISMATCH');
  }
  sameHash(p.target.diff_sha256, trustedTarget.diff_sha256, 'DIFF_MISMATCH');
  if (seenReviewIds.has(p.review_id) || seenNonces.has(p.nonce)) reject('REPLAY_DETECTED');

  const keyRecord = trustedKeys.get(s.key_id);
  if (s.algorithm !== 'Ed25519' || !IDENT.test(s.key_id) || !keyRecord ||
      keyRecord.issuer !== p.issuer || keyRecord.reviewerId !== p.analysis.reviewer_id) reject('UNTRUSTED_SIGNER');
  if (!Buffer.isBuffer(reportBytes)) reject('MISSING_RAW_REPORT');
  sameHash(p.analysis.report_sha256, createHash('sha256').update(reportBytes).digest('hex'), 'REPORT_MISMATCH');
  if (typeof s.value !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(s.value)) reject('MALFORMED_SIGNATURE');
  const rawSignature = Buffer.from(s.value, 'base64');
  if (rawSignature.length !== 64) reject('MALFORMED_SIGNATURE');
  // Node's base64 parser accepts non-zero unused pad bits. Refuse alternate
  // encodings of the same signature bytes to avoid transport malleability.
  if (rawSignature.toString('base64') !== s.value) reject('MALFORMED_SIGNATURE');
  let valid = false;
  try {
    const key = createPublicKey(keyRecord.publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') reject('UNTRUSTED_KEY_TYPE');
    valid = verifySignature(null, Buffer.from(canonicalJson(p), 'utf8'), key, rawSignature);
  } catch (e) {
    if (e.message === 'UNTRUSTED_KEY_TYPE') throw e;
    reject('SIGNATURE_VERIFICATION_FAILED');
  }
  if (!valid) reject('SIGNATURE_VERIFICATION_FAILED');

  // No replay recording here. Only an atomic, authorized publisher may consume
  // a nonce; NO PUBLISHER EXISTS IN THIS PHASE.
  return Object.freeze({
    cryptographicIntegrityVerified: true,
    reviewIndependenceVerified: false,
    approvalAuthorized: false,
    dispositionClaimedBySigner: p.analysis.disposition,
    attestationSha256: createHash('sha256').update(canonicalJson(envelope)).digest('hex'),
    reviewId: p.review_id,
    nonce: p.nonce
  });
}
