import { createHash, createPublicKey, verify as verifyRsa, timingSafeEqual } from 'node:crypto';

const EXPECTED_FIELDS = [
  'app_bot_id', 'base_sha', 'completed_at', 'head_sha',
  'installation_id', 'nonce', 'pr_number', 'provenance_ref',
  'report_sha256', 'repository', 'reviewer_run_id', 'verdict'
];
const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const B64URL = /^[a-zA-Z0-9_-]+$/;
const NONCE = /^[0-9a-f]{32,128}$/;
const RUN = /^[A-Za-z0-9_:-]{8,180}$/;
const PROVENANCE = /^[A-Za-z0-9_:/.-]{8,240}$/;
const ISO_UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;

function deny(code) { throw new Error(code); }
function digest(buffer) { return createHash('sha256').update(buffer).digest('hex'); }
function sameSha(a,b) {
  return typeof a==='string' && typeof b==='string' &&
    SHA256.test(a) && SHA256.test(b) &&
    timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
}

/**
 * This canonicalization is intentionally the RSA/native-review adapter's
 * sorted top-level-object encoding, NOT the Ed25519 analysis wire codec.
 * Signing is done by a SEPARATE pinned RSA identity, not the GitHub App key.
 */
export function nativePayloadBytes(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) ||
      JSON.stringify(Object.keys(payload).sort()) !== JSON.stringify(EXPECTED_FIELDS)) {
    deny('NATIVE_INVALID_FIELDS');
  }
  if (payload.repository!=='deenkids7-dev/deenkids' ||
      payload.app_bot_id!==340237276 ||
      payload.installation_id!==169674558 ||
      !Number.isSafeInteger(payload.pr_number) || payload.pr_number<1 ||
      !SHA40.test(payload.head_sha) || !SHA40.test(payload.base_sha) ||
      (payload.verdict!=='PASS' && payload.verdict!=='FAIL') ||
      !SHA256.test(payload.report_sha256) ||
      !NONCE.test(payload.nonce) ||
      !RUN.test(payload.reviewer_run_id) ||
      !PROVENANCE.test(payload.provenance_ref) ||
      typeof payload.completed_at!=='string' ||
      !ISO_UTC.test(payload.completed_at) ||
      !Number.isFinite(Date.parse(payload.completed_at)) ||
      new Date(Date.parse(payload.completed_at)).toISOString().replace('.000Z','Z')!==payload.completed_at) {
    deny('NATIVE_INVALID_PAYLOAD');
  }
  return Buffer.from(JSON.stringify(Object.fromEntries(
    Object.entries(payload).sort(([a],[b])=>a<b?-1:a>b?1:0)
  )),'utf8');
}

/**
 * Pure formatter for an already RSA-signed native review artifact.
 * NO review publication, GitHub token handling, approval policy or signing.
 * The caller cannot infer independence or authorization from returned flags.
 */
export function formatNativeReviewFixture({
  payload, reportText, signatureBase64Url, pinnedPublicKeyPem, pinnedKeySha256
}) {
  if (typeof reportText!=='string' || !reportText.length ||
      Buffer.byteLength(reportText,'utf8')>64*1024 ||
      reportText.includes('\u0000') || reportText.includes('\r')) {
    deny('NATIVE_INVALID_REPORT');
  }
  const reportBytes = Buffer.from(reportText,'utf8');
  if (!sameSha(payload?.report_sha256,digest(reportBytes))) {
    deny('NATIVE_REPORT_MISMATCH');
  }
  const signedBytes=nativePayloadBytes(payload);
  if (typeof signatureBase64Url!=='string' ||
      !B64URL.test(signatureBase64Url) ||
      Buffer.from(signatureBase64Url,'base64url').toString('base64url')!==signatureBase64Url) {
    deny('NATIVE_INVALID_SIGNATURE_ENCODING');
  }
  let key;
  try {
    key=createPublicKey(pinnedPublicKeyPem);
    if (key.asymmetricKeyType!=='rsa' ||
        (key.asymmetricKeyDetails?.modulusLength||0)<2048) {
      deny('NATIVE_UNTRUSTED_KEY');
    }
  } catch { deny('NATIVE_UNTRUSTED_KEY'); }
  const der=key.export({type:'spki',format:'der'});
  if (!sameSha(pinnedKeySha256,digest(der))) deny('NATIVE_UNTRUSTED_KEY');
  const signature=Buffer.from(signatureBase64Url,'base64url');
  if (!verifyRsa('sha256',signedBytes,key,signature)) {
    deny('NATIVE_BAD_RSA_SIGNATURE');
  }
  const envelope=Buffer.from(JSON.stringify({
    payload,signature:signatureBase64Url
  }), 'utf8').toString('base64url');
  const reviewBody='<!-- devfactory-reviewer-b-native:v1:'+envelope+' -->\n'+reportText;
  if (reviewBody.length>120000) deny('NATIVE_REVIEW_BODY_TOO_LARGE');
  return Object.freeze({
    reviewBody, dispositionClaimedBySigner:payload.verdict,
    // A formatter must never decide the event to send to GitHub.
    publishEvent:null,
    cryptographicIntegrityVerified:true,
    reviewIndependenceVerified:false,
    approvalAuthorized:false
  });
}
