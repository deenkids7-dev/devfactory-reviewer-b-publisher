import { createHash, timingSafeEqual } from 'node:crypto';
import { inspect } from 'node:util';
import { canonicalJson } from '../src/canonical.mjs';

// Pure construction and comparison of a SUBJECT to be signed by a future
// reviewed, trusted GitHub workflow. This is NOT attestation verification,
// independent code analysis, authorization, a publisher, or a live review.
const PRIVATE_REPO='deenkids7-dev/deenkids';
const PUBLIC_REPO='devfactory-reviewer-trust/devfactory-reviewer-b-publisher';
const WORKFLOW='.github/workflows/reviewer-b-live-review.yml';
const SHA40=/^[0-9a-f]{40}$/;
const HEX64=/^[0-9a-f]{64}$/;
const RUN=/^[A-Za-z0-9_:-]{8,180}$/;
const ENGINE=new Set(['local-qwen','gemini-code-assist','semgrep-ce']);
const KEYS=['schema','target','report_sha256','run_id','engine','analyzer_sha256',
  'builder_repository','builder_workflow','builder_source_sha'];
const TARGET_KEYS=['repository','repository_id','pr_number','head_sha',
  'base_sha','diff_sha256'];
function deny(code){throw Error(code);}
function exactKeys(value,keys){
  return value && typeof value==='object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort())===
      JSON.stringify([...keys].sort());
}
function sha40(value){return typeof value==='string' && SHA40.test(value);}
function sha256(value){return typeof value==='string' && HEX64.test(value);}
function bindTarget(value){
  if(!exactKeys(value,TARGET_KEYS) ||
     value.repository!==PRIVATE_REPO || value.repository_id!==1282086207 ||
     !Number.isSafeInteger(value.pr_number) || value.pr_number<1 ||
     !sha40(value.head_sha) || !sha40(value.base_sha) ||
     !sha256(value.diff_sha256)) deny('KEYLESS_TARGET_INVALID');
  return Object.fromEntries(TARGET_KEYS.map(k=>[k,value[k]]));
}
function bindFields({target,reportSha256,runId,engine,analyzerSha256,
                     builderSourceSha}={}){
  const t=bindTarget(target);
  if(!sha256(reportSha256)||typeof runId!=='string'||!RUN.test(runId)||
     typeof engine!=='string'||!ENGINE.has(engine)||
     !sha256(analyzerSha256)||!sha40(builderSourceSha))
    deny('KEYLESS_REVIEW_SCOPE_INVALID');
  return {
    schema:'devfactory.reviewer-b.keyless-subject.v1',
    target:t,report_sha256:reportSha256,run_id:runId,engine,
    analyzer_sha256:analyzerSha256,
    builder_repository:PUBLIC_REPO,builder_workflow:WORKFLOW,
    builder_source_sha:builderSourceSha
  };
}
function digest(b){return createHash('sha256').update(b).digest('hex');}
function equalsHex(a,b){
  return sha256(a)&&sha256(b)&&
    timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
}
/** Build an exact-SHA subject WITHOUT approving private source exposure.
 * Caller MUST obtain target from authenticated immutable GitHub reads.
 * Do NOT put any private report in a public attestation; attest this subject
 * only after the workflow and operator permit disclosure of target metadata.
 */
export function prepareKeylessReviewSubject(args={}){
  const subject=bindFields(args);
  const privateSubject=Buffer.from(canonicalJson(subject),'utf8');
  const safe={
    subjectSha256:digest(privateSubject),
    hasVerifiedGitHubAttestation:false,
    executionOriginVerified:false,
    reviewIndependenceVerified:false,
    approvalAuthorized:false,
    publishEvent:null
  };
  Object.defineProperties(safe,{
    subjectBytes:{enumerable:false,configurable:false,
      get:()=>Buffer.from(privateSubject)},
    toJSON:{enumerable:false,configurable:false,
      value:()=>({...Object.fromEntries(Object.entries(safe)),
        subjectBytes:'[UNVERIFIED_ATTESTATION_SUBJECT]'})},
    [inspect.custom]:{enumerable:false,configurable:false,
      value:()=> '[KeylessReviewSubject: UNVERIFIED; NOT AUTHORIZED]'}
  });
  return Object.freeze(safe);
}
/** Prove ONLY that candidate bytes match independently expected PR/report/
 * workflow identity. Does not inspect or authenticate Sigstore signatures.
 * The actual trust decision requires gh attestation verify with pinned signer,
 * source ref, source digest and protected environment provenance.
 */
export function compareKeylessReviewSubject({subjectBytes,expected}={}){
  if(!Buffer.isBuffer(subjectBytes)||subjectBytes.length<150||
     subjectBytes.length>4096)deny('KEYLESS_SUBJECT_BYTES_INVALID');
  const raw=subjectBytes.toString('utf8');
  if(!Buffer.from(raw,'utf8').equals(subjectBytes)||raw.includes('\u0000'))
    deny('KEYLESS_SUBJECT_ENCODING_INVALID');
  let observed;
  try{observed=JSON.parse(raw);}catch{deny('KEYLESS_SUBJECT_JSON_INVALID');}
  if(!exactKeys(observed,KEYS)||!exactKeys(observed.target,TARGET_KEYS))
    deny('KEYLESS_SUBJECT_FIELDS_INVALID');
  const scope=bindFields(expected);
  const wanted=Buffer.from(canonicalJson(scope),'utf8');
  if(!subjectBytes.equals(Buffer.from(canonicalJson(observed),'utf8'))||
     !equalsHex(digest(subjectBytes),digest(wanted))||
     !subjectBytes.equals(wanted))deny('KEYLESS_SUBJECT_SCOPE_MISMATCH');
  return Object.freeze({
    subjectSha256:digest(subjectBytes),
    boundToExpectedScope:true,
    hasVerifiedGitHubAttestation:false,
    executionOriginVerified:false,
    reviewIndependenceVerified:false,
    approvalAuthorized:false,
    publishEvent:null
  });
}
