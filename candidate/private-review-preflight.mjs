import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { createReadOnlyGitHubTransport } from './github-read-only.mjs';
import { observePrSnapshot } from '../src/github-pr-observer.mjs';
import { runFailOnlyStaticDiffAudit } from './fail-only-static-audit.mjs';

function deny(code) { throw new Error(code); }

/**
 * Secret-free orchestrator, to be executed ONLY in a future privileged job
 * with an independently provisioned installation token. Does no write, no
 * model inference and no publication. The raw private diff never appears in
 * the returned object: all private bytes are kept inside this call.
 *
 * Caller must separately approve exposure before ANY use of the model
 * interface. This preflight is not a code review or an approval.
 */
export async function runReadOnlyReviewPreflight({
  prNumber, runId, installationToken, fetchImpl=fetch
}={}) {
  const transport=createReadOnlyGitHubTransport({
    installationToken,fetchImpl
  });
  let rawDiffBytes;
  const request=async ({url,method,accept,maxBytes})=>{
    const response=await transport({url,method,accept,maxBytes});
    if(accept==='application/vnd.github.diff'){
      if(rawDiffBytes!==undefined) deny('PREFLIGHT_REPEATED_DIFF');
      rawDiffBytes=Buffer.from(response.body);
    }
    return response;
  };
  const snapshot=await observePrSnapshot({prNumber,request});
  if(!Buffer.isBuffer(rawDiffBytes)||rawDiffBytes.length<1 ||
     createHash('sha256').update(rawDiffBytes).digest('hex')!==snapshot.diff_sha256){
    deny('PREFLIGHT_DIFF_MISMATCH');
  }
  const audit=runFailOnlyStaticDiffAudit({
    diffBytes:rawDiffBytes,runId
  });
  const summary=Object.freeze({
    repository:snapshot.repository,
    repositoryId:snapshot.repository_id,
    prNumber:snapshot.pr_number,
    headSha:snapshot.head_sha,
    baseSha:snapshot.base_sha,
    diffSha256:snapshot.diff_sha256
  });
  const report=Buffer.from(audit.reportBytes);
  // Private file names remain sensitive even when no code line is echoed.
  const output={
    target:summary,staticDisposition:audit.provisionalState,
    blockingFindings:audit.blockingFindings,
    semanticAnalysisCompleted:false,independentReviewVerified:false,
    approvalAuthorized:false,publishEvent:null
  };
  Object.defineProperties(output,{
    staticReportBytes:{enumerable:false,configurable:false,
      get:()=>Buffer.from(report)},
    toJSON:{enumerable:false,configurable:false,
      value:()=>({...Object.fromEntries(Object.entries(output)),
        staticReportBytes:'[REDACTED_PRIVATE_REPORT]'})},
    [inspect.custom]:{enumerable:false,configurable:false,
      value:()=> '[ReadOnlyReviewPreflight: PRIVATE REPORT REDACTED; NOT AUTHORIZED]'}
  });
  return Object.freeze(output);
}
