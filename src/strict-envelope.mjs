import { canonicalJson } from './canonical.mjs';
import { verifyAttestation } from './verify-attestation.mjs';

// Strict byte-level boundary for untrusted attestation artifacts.
// Canonical encoding is a LOCAL protocol, not RFC 8785/JCS.
const MAX_ATTESTATION_BYTES = 64 * 1024;
const MAX_REPORT_BYTES = 2 * 1024 * 1024;

function deny(code) { throw new Error(code); }

export function parseCanonicalEnvelope(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 ||
      bytes.length > MAX_ATTESTATION_BYTES) deny('INVALID_ATTESTATION_SIZE');
  const text = bytes.toString('utf8');
  // Reject non-UTF8 and noncanonical bytes, whitespace, duplicate keys,
  // ambiguous JSON representations and dangerous object prototypes.
  if (!Buffer.from(text, 'utf8').equals(bytes)) deny('INVALID_UTF8');
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    deny('INVALID_ATTESTATION_JSON');
  }
  let canonical;
  try {
    canonical = canonicalJson(parsed);
  } catch {
    deny('INVALID_ATTESTATION_SCHEMA_ENCODING');
  }
  if (canonical !== text) deny('NONCANONICAL_ATTESTATION');
  return parsed;
}

export function verifySerializedAttestation({
  envelopeBytes, reportBytes, trustedKeys, trustedTarget,
  seenReviewIds, seenNonces, now
}) {
  if (!Buffer.isBuffer(reportBytes) || reportBytes.length < 1 ||
      reportBytes.length > MAX_REPORT_BYTES) deny('INVALID_REPORT_SIZE');
  const envelope = parseCanonicalEnvelope(envelopeBytes);
  // No GitHub writes, no replay-state mutation and never approval authority.
  return verifyAttestation({
    envelope, reportBytes, trustedKeys, trustedTarget,
    seenReviewIds, seenNonces, now
  });
}
