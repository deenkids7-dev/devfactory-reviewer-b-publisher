import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { nativePayloadBytes, formatNativeReviewFixture } from '../src/native-review-wire.mjs';

// Format-only RSA marker signature. DOES NOT POST, APPROVE, or attest review
// independence; caller MUST obtain all provenance from separate trust source.
const HEX64=/^[0-9a-f]{64}$/;
function deny(code){throw new Error(code);}
function sha(data){return createHash('sha256').update(data).digest('hex');}

/**
 * Native GitHub review RSA-SHA256 signing key MUST BE DISTINCT from the
 * GitHub App JWT private key and the analyzer Ed25519 signing identity.
 *
 * The signer key's fingerprint must have been independently pinned, never
 * copied from the untrusted report, PR description or test fixture.
 */
export function signNativeMarkerOnly({
  payload,reportText,nativeSignerPrivateKeyPem,pinnedSignerSpkiSha256,
  pinnedAppSpkiSha256
}={}) {
  if(typeof nativeSignerPrivateKeyPem!=='string' ||
      nativeSignerPrivateKeyPem.length<100 ||
      nativeSignerPrivateKeyPem.length>16000 ||
      typeof pinnedSignerSpkiSha256!=='string'||
      !HEX64.test(pinnedSignerSpkiSha256) ||
      typeof pinnedAppSpkiSha256!=='string'||!HEX64.test(pinnedAppSpkiSha256)) {
    deny('NATIVE_SIGNER_UNPROVISIONED');
  }
  let key;
  try {
    key=createPrivateKey(nativeSignerPrivateKeyPem);
    if(key.asymmetricKeyType!=='rsa' ||
       (key.asymmetricKeyDetails?.modulusLength||0)<2048)
       deny('NATIVE_SIGNER_KEY_DENIED');
  } catch {deny('NATIVE_SIGNER_INVALID_PRIVATE_KEY');}
  const publicKey=createPublicKey(key);
  const spkiSha256=sha(publicKey.export({type:'spki',format:'der'}));
  if(spkiSha256!==pinnedSignerSpkiSha256)
    deny('NATIVE_SIGNER_FINGERPRINT_MISMATCH');
  if(spkiSha256===pinnedAppSpkiSha256)
    deny('NATIVE_SIGNER_REUSES_APP_JWT_KEY');
  // Only signed FAIL fixtures are permitted until external provenance + HUMAN_GO exist.\n  if(payload?.verdict!=='FAIL')deny('NATIVE_SIGNER_PASS_NOT_AUTHORIZED');\n  const canonical=nativePayloadBytes(payload);
  const signatureBase64Url=sign('RSA-SHA256',canonical,key).toString('base64url');
  const wire=formatNativeReviewFixture({
    payload,reportText,signatureBase64Url,
    pinnedPublicKeyPem:publicKey.export({type:'spki',format:'pem'}),
    pinnedKeySha256:pinnedSignerSpkiSha256
  });
  return Object.freeze({
    reviewBody:wire.reviewBody,
    signerSpkiSha256:spkiSha256,
    dispositionClaimedBySigner:payload.verdict,
    // No GitHub write event: native review must remain unpublishable.
    publishEvent:null,
    approvalAuthorized:false,
    reviewIndependenceVerified:false
  });
}
