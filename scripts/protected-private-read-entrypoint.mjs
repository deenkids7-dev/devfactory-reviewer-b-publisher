import { runScopedPrivateReadPreflight } from '../candidate/scoped-private-read-preflight.mjs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// This executable has no GitHub write operation or model/provider access.
// It is ONLY intended to be executed from reviewed public Publisher main,
// inside the separately approved GitHub environment reviewer-b-publish.
// Never print raw errors: upstream HTTP/runtime exceptions may be sensitive.
const PREFIX='PROTECTED_PRIVATE_PREFLIGHT';
const SHA40=/^[0-9a-f]{40}$/;
const RUN=/^[1-9][0-9]{0,18}$/;
const PR=/^[1-9][0-9]{0,9}$/;
export function approvedReadOnlyExecutionContext(env={}){
  if(!env || typeof env!=='object' || Array.isArray(env))return false;
  return env.GITHUB_REPOSITORY==='devfactory-reviewer-trust/devfactory-reviewer-b-publisher'
    && env.GITHUB_REF==='refs/heads/main'
    && env.GITHUB_EVENT_NAME==='workflow_dispatch'
    && env.GITHUB_ACTOR==='devfactory-reviewer-service'
    && typeof env.GITHUB_SHA==='string'&&SHA40.test(env.GITHUB_SHA)
    && typeof env.GITHUB_RUN_ID==='string'&&RUN.test(env.GITHUB_RUN_ID)
    && typeof env.GITHUB_RUN_ATTEMPT==='string'&&RUN.test(env.GITHUB_RUN_ATTEMPT)
    && typeof env.REVIEWER_B_TARGET_PR==='string'&&PR.test(env.REVIEWER_B_TARGET_PR)
    && Number.isSafeInteger(Number(env.REVIEWER_B_TARGET_PR))
    && Number(env.REVIEWER_B_TARGET_PR)<=2147483647;
}
export async function executeProtectedReadOnlyPreflight(options={}){
  // Untrusted optional argument objects must never throw before the
  // context check. The CLI can only run in one exact trusted workflow.
  const safeOptions=options && typeof options==='object' && !Array.isArray(options)
    ?options:{};
  const {env={},fetchImpl=globalThis.fetch,now=Date.now()}=safeOptions;
  if(!approvedReadOnlyExecutionContext(env))
    return Object.freeze({code:'CONTEXT_DENIED',ok:false});
  const privateKeyPem=env.REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM;
  if(typeof privateKeyPem!=='string'||privateKeyPem.length<100)
    return Object.freeze({code:'CREDENTIAL_NOT_PROVISIONED',ok:false});
  try{
    const result=await runScopedPrivateReadPreflight({
      prNumber:Number(env.REVIEWER_B_TARGET_PR),
      runId:'gh-'+env.GITHUB_RUN_ID+'-'+env.GITHUB_RUN_ATTEMPT,
      appPrivateKeyPem:privateKeyPem,now,fetchImpl
    });
    if(result?.approvalAuthorized!==false||result?.publishEvent!==null||
       result?.independentReviewVerified!==false)
      return Object.freeze({code:'FORBIDDEN_AUTHORITY',ok:false});
    return Object.freeze({
      code:result.blockingFindings>0?'STATIC_FINDINGS_BLOCK':'INCONCLUSIVE_NOT_REVIEWED',
      ok:result.blockingFindings===0,
      reviewApproved:false
    });
  }catch{
    // Reject all unauthorized HTTP/credential/diff errors without revealing
    // a token, private source, or underlying sensitive exception message.
    return Object.freeze({code:'READ_PROOF_FAILED',ok:false});
  }
}

if(process.argv[1] && fileURLToPath(import.meta.url)===resolve(process.argv[1])){
  try{
    const result=await executeProtectedReadOnlyPreflight({env:process.env});
    console.log(PREFIX+'_'+result.code);
    if(!result.ok)process.exitCode=1;
  }catch{
    // Fail closed without exposing unexpected error messages or secrets.
    console.log(PREFIX+'_READ_PROOF_FAILED');
    process.exitCode=1;
  }
}
