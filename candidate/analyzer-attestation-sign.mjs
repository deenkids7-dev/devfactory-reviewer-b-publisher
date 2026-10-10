import {
  createPrivateKey, createPublicKey, createHash, sign as signEd25519
} from 'node:crypto';
import { canonicalJson } from '../src/canonical.mjs';
import { validateReviewerFindings } from '../src/findings-contract.mjs';
import { verifySerializedAttestation } from '../src/strict-envelope.mjs';

const SHA40=/^[0-9a-f]{40}$/;
const HEX64=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ISO=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
function deny(code){throw Error(code);}
function sha(b){return createHash('sha256').update(b).digest('hex');}
/**
 * Dormant independent-engine-only report signer, NOT authorized in Publisher
 * or the MSI. It proves only integrity of a claimed review. The caller must
 * provide separately authenticated runner provenance and the trusted GitHub
 * snapshot. The signer MUST NOT be runnable by a code-author-controlled job
 * using the Publisher's protected RSA/JWT credentials.
 */
export function signAnalyzerAttestationFixture({
  reportBytes,changedPaths,target,runId,issuer,reviewerId,
  keyId,ed25519PrivateKeyPem,pinnedEd25519SpkiSha256,
  nonce,issuedAt,expiresAt,now=Date.now()
}={}){
  // Date.parse alone is not sufficient: invalid dates can yield NaN or be
  // normalized (e.g. February 30). Require canonical UTC seconds roundtrips.
  const issued=typeof issuedAt==='string'&&ISO.test(issuedAt)?
    Date.parse(issuedAt):NaN;
  const expires=typeof expiresAt==='string'&&ISO.test(expiresAt)?
    Date.parse(expiresAt):NaN;
  if(!Buffer.isBuffer(reportBytes)||!ID.test(runId)||!ID.test(issuer)||
     !ID.test(reviewerId)||!ID.test(keyId)||!UUID.test(nonce)||
     !Number.isFinite(now)||!Number.isFinite(issued)||
     !Number.isFinite(expires)||
     new Date(issued).toISOString().replace('.000Z','Z')!==issuedAt||
     new Date(expires).toISOString().replace('.000Z','Z')!==expiresAt||
     expires<=now||expires<=issued||issued>now+60000||
     expires-issued>15*60000||
     typeof ed25519PrivateKeyPem!=='string'||
     ed25519PrivateKeyPem.length<100||ed25519PrivateKeyPem.length>16000||
     typeof pinnedEd25519SpkiSha256!=='string'||
     !HEX64.test(pinnedEd25519SpkiSha256)){
    deny('ANALYZER_SIGNER_INPUT_INVALID');
  }
  if(!target||target.repository!=='deenkids7-dev/deenkids'||
     target.repository_id!==1282086207||
     !Number.isSafeInteger(target.pr_number)||target.pr_number<1||
     !SHA40.test(target.head_sha)||!SHA40.test(target.base_sha)||
     !HEX64.test(target.diff_sha256)){
    deny('ANALYZER_SIGNER_TARGET_UNVERIFIED');
  }
  const findings=validateReviewerFindings({
    reportBytes,changedPaths
  });
  if(findings.runId!==runId)deny('ANALYZER_SIGNER_RUN_ID_MISMATCH');
  let key;
  try{
    key=createPrivateKey(ed25519PrivateKeyPem);
    if(key.asymmetricKeyType!=='ed25519')deny('BAD_TYPE');
  }catch{deny('ANALYZER_SIGNER_WRONG_PRIVATE_KEY');}
  const pub=createPublicKey(key);
  const fingerprint=sha(pub.export({type:'spki',format:'der'}));
  if(fingerprint!==pinnedEd25519SpkiSha256)
    deny('ANALYZER_SIGNER_KEY_FINGERPRINT_MISMATCH');
  const payload={
    schema:'devfactory.reviewer-b.attestation.v1',
    issuer,review_id:runId,nonce,issued_at:issuedAt,expires_at:expiresAt,
    target:{
      repository:target.repository,repository_id:target.repository_id,
      pr_number:target.pr_number,head_sha:target.head_sha,
      base_sha:target.base_sha,diff_sha256:target.diff_sha256
    },
    analysis:{
      reviewer_id:reviewerId,
      disposition:findings.blockingFindingCount?'FAIL':'BLOCKED',
      report_sha256:sha(reportBytes)
    }
  };
  const signed=signEd25519(null,Buffer.from(canonicalJson(payload)),key)
    .toString('base64');
  const envelopeBytes=Buffer.from(canonicalJson({
    payload,signature:{algorithm:'Ed25519',key_id:keyId,value:signed}
  }));
  // Self-check is only cryptographic: independent execution is UNVERIFIED.
  const result=verifySerializedAttestation({
    envelopeBytes,reportBytes,
    trustedKeys:new Map([[keyId,{
      issuer,reviewerId,publicKeyPem:pub.export({type:'spki',format:'pem'}),
      spkiSha256:pinnedEd25519SpkiSha256
    }]]),
    trustedTarget:target,
    seenReviewIds:new Set(),seenNonces:new Set(),now
  });
  if(!result.cryptographicIntegrityVerified)
    deny('ANALYZER_SIGNER_SELFTEST_FAILED');
  return Object.freeze({
    envelopeBytes,
    signedDisposition:payload.analysis.disposition,
    reviewerIndependenceVerified:false,
    approvalAuthorized:false
  });
}
