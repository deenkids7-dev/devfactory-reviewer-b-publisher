import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {approvedReadOnlyExecutionContext} from './protected-private-read-entrypoint.mjs';
import {createReviewerBAppJwt,createScopedReviewerBInstallationToken}
  from '../candidate/github-app-auth.mjs';
import {runReadOnlyReviewPreflight}
  from '../candidate/private-review-preflight.mjs';
import {publishNonAuthorizingNativeReview}
  from './protected-native-comment-publisher.mjs';

const LABEL='PROTECTED_NATIVE_COMMENT';
const PR='899';
function fail(code){return Object.freeze({ok:false,code});}
/** No user input or untrusted PR content can authorize a write.
 * Only a protected-main marker-scoped push by service account, after
 * reviewer-b-publish environment approval, can run this entrypoint.
 * Public workflow CI never imports/calls this executable.
 */
export function canRunProtectedNativeComment(env){
  return approvedReadOnlyExecutionContext(env)&&
    env.GITHUB_EVENT_NAME==='push'&&
    env.REVIEWER_B_TARGET_PR===PR;
}
export async function executeNativeCommentOnlyCanary({
  env={},now=Date.now(),fetchImpl=globalThis.fetch
}={}){
  if(!canRunProtectedNativeComment(env))
    return fail('CONTEXT_DENIED');
  const pem=env.REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM;
  if(typeof pem!=='string'||pem.length<100)
    return fail('CREDENTIAL_NOT_PROVISIONED');
  try{
    const runId='gh-'+env.GITHUB_RUN_ID+'-'+env.GITHUB_RUN_ATTEMPT;
    const jwt=createReviewerBAppJwt({privateKeyPem:pem,now});
    const read=await createScopedReviewerBInstallationToken({
      appJwt:jwt,purpose:'reviewRead',now,fetchImpl
    });
    const preflight=await runReadOnlyReviewPreflight({
      prNumber:Number(PR),runId,installationToken:read.token,fetchImpl
    });
    if(preflight.staticDisposition!=='INCONCLUSIVE'||
       preflight.blockingFindings!==0||
       preflight.approvalAuthorized!==false||
       preflight.independentReviewVerified!==false||
       preflight.publishEvent!==null)
      return fail('STATIC_PREFLIGHT_NOT_CLEARED');
    // Mint a new token limited to PRIVATE Pull requests:WRITE, with no
    // PRIVATE code/read permission. The App's primary key never leaves env.
    const writer=await createScopedReviewerBInstallationToken({
      appJwt:jwt,purpose:'publish',now,fetchImpl
    });
    const posted=await publishNonAuthorizingNativeReview({
      privatePreflight:preflight,runId,
      expectedHeadSha:preflight.target.headSha,
      readToken:read.token,writeToken:writer.token,
      approvedProtectedComment:true,fetchImpl
    });
    if(posted.event!=='COMMENTED'||posted.evidenceClass!=='NATIVE_COMMENT_ONLY'||
       posted.approvalAuthorized!==false||
       posted.independentReviewVerified!==false||
       posted.humanGoVerified!==false)
      return fail('POST_PROOF_UNVERIFIED');
    return Object.freeze({
      ok:true,code:'NATIVE_COMMENT_ONLY_VERIFIED',
      prNumber:posted.prNumber,nativeReviewId:posted.nativeReviewId,
      reviewApproved:false,independentReviewVerified:false,
      humanGoVerified:false
    });
  }catch{
    // No raw HTTP errors, PEM, installation tokens, source paths or findings
    // are allowed into PUBLIC Publisher Actions logs.
    return fail('NATIVE_COMMENT_PROOF_FAILED');
  }
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===resolve(process.argv[1])){
  try{
    const result=await executeNativeCommentOnlyCanary({env:process.env});
    console.log(LABEL+'_'+result.code);
    if(!result.ok)process.exitCode=1;
  }catch{
    console.log(LABEL+'_NATIVE_COMMENT_PROOF_FAILED');
    process.exitCode=1;
  }
}
