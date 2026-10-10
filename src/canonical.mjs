/** Deterministic JSON representation for attestation payloads.
 * Local protocol, NOT RFC 8785/JCS. Signer and verifier MUST use same codec.
 * Only safe integers are accepted.
 */
export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }
  if (typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Object.keys(value).sort();
    if (keys.some(k => k === '__proto__' || k === 'constructor' || k === 'prototype')) {
      throw new Error('UNSAFE_OBJECT_KEY');
    }
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
  }
  throw new Error('UNSUPPORTED_CANONICAL_VALUE');
}
