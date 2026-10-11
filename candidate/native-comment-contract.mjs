import { createHash } from 'node:crypto';

const REPO='deenkids7-dev/deenkids';
const REPO_ID=1282086207;
const SHA40=/^[a-f0-9]{40}$/;
const SHA64=/^[a-f0-9]{64}$/;
const RUN=/^gh-[1-9][0-9]{0,18}-[1-9][0-9]{0,18}$/;
const MARKER=/^<!-- devfactory-reviewer-b-comment-only:v1:[A-Za-z0-9_-]+ -->\n/;
function deny(code){throw Error(code);}
const digest=b=>createHash('sha256').update(b).digest('hex');
/**
 * PRIVATE PR COMMENT ONLY; not independent review or automated acceptance.
 * Message has no source, findings, credentials, or signed review authority.
 * Never emits APPROVE / REQUEST_CHANGES, never claims a Sigstore report.
 */
export function prepareNonAuthorizingNativeComment({
  privatePreflight,runId,expectedHeadSha
}={}){
  const p=privatePreflight,t=p?.target;
  if(!p||!t||t.repository!==REPO||t.repositoryId!==REPO_ID||
     !Number.isSafeInteger(t.prNumber)||t.prNumber<1||
     typeof expectedHeadSha!=='string'||!SHA40.test(expectedHeadSha)||
     t.headSha!==expectedHeadSha||
     typeof t.baseSha!=='string'||!SHA40.test(t.baseSha)||
     typeof t.diffSha256!=='string'||!SHA64.test(t.diffSha256)||
     typeof runId!=='string'||!RUN.test(runId)||
     p.staticDisposition!=='INCONCLUSIVE'||
     p.blockingFindings!==0||p.semanticAnalysisCompleted!==false||
     p.independentReviewVerified!==false||
     p.approvalAuthorized!==false||p.publishEvent!==null||
     typeof p.staticReportBytes==='undefined'||
     !Buffer.isBuffer(p.staticReportBytes))
    deny('NATIVE_COMMENT_UNTRUSTED_PREFLIGHT');
  const reportSha=digest(p.staticReportBytes);
  const marker=digest(Buffer.from([t.prNumber,expectedHeadSha,runId,reportSha].join(':'))).slice(0,32);
  const body='<!-- devfactory-reviewer-b-comment-only:v1:'+marker+' -->\n'+
    'Reviewer B — protected static preflight (non-authorizing)\n\n'+
    'Result: INCONCLUSIVE; semantic review, independent witness and '+
    'attested report are NOT verified.\n'+
    'Target HEAD: '+expectedHeadSha+'\n'+
    'Private diff SHA-256: '+t.diffSha256+'\n'+
    'Private static report SHA-256: '+reportSha+'\n'+
    'Protected workflow run: '+runId+'\n\n'+
    'This is a native COMMENTED record only, never an approval, '+
    'HUMAN_GO or authorization for DevFactory Merge Executor.';
  if(body.length>2000||!MARKER.test(body))
    deny('NATIVE_COMMENT_INVALID_BODY');
  return Object.freeze({
    prNumber:t.prNumber,headSha:expectedHeadSha,
    reportSha256:reportSha,diffSha256:t.diffSha256,
    marker,body,event:'COMMENT',
    evidenceClass:'NATIVE_COMMENT_ONLY',approvalAuthorized:false,
    independentReviewVerified:false
  });
}
