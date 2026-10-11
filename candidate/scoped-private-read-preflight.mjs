import { createReviewerBAppJwt,createScopedReviewerBInstallationToken }
  from './github-app-auth.mjs';
import {runReadOnlyReviewPreflight} from './private-review-preflight.mjs';

function deny(code){throw Error(code);}
/**
 * Composes the EXISTING GitHub App authentication with the EXISTING exact-SHA
 * read-only preflight. This has NO entry point or workflow; it must be called
 * only by a future independently reviewed protected Publisher job.
 *
 * The key MUST come from the protected environment, never from source text,
 * PR comments, untrusted workflow inputs or the DevFactory MSI.
 * It mints ONLY a Contents:read + Pull requests:read installation token.
 * No model calls, source disclosure, review POST, merge, PASS or HUMAN_GO.
 */
export async function runScopedPrivateReadPreflight({
  prNumber,runId,appPrivateKeyPem,now=Date.now(),fetchImpl=fetch
}={}){
  if(!Number.isSafeInteger(prNumber)||prNumber<1||prNumber>2147483647||
     typeof runId!=='string'||!(/^[A-Za-z0-9_:-]{8,180}$/).test(runId)||
     typeof appPrivateKeyPem!=='string'||appPrivateKeyPem.length<100||
     typeof fetchImpl!=='function'||!Number.isFinite(now)||now<1)
    deny('PROTECTED_PREFLIGHT_INVALID_INPUT');
  const jwt=createReviewerBAppJwt({privateKeyPem:appPrivateKeyPem,now});
  const scoped=await createScopedReviewerBInstallationToken({
    appJwt:jwt,purpose:'reviewRead',now,fetchImpl
  });
  // No elevated token retained outside the scope of this call.
  // The existing result removes raw diff/finding paths from enumeration.
  const result=await runReadOnlyReviewPreflight({
    prNumber,runId,installationToken:scoped.token,fetchImpl
  });
  return result;
}
