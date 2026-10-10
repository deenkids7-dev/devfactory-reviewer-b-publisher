import { canonicalJson } from '../src/canonical.mjs';
import { validateReviewerFindings } from '../src/findings-contract.mjs';

function deny(code){throw Error(code);}
function parseReport(bytes,changedPaths){
  const validated=validateReviewerFindings({reportBytes:bytes,changedPaths});
  return {value:JSON.parse(bytes.toString('utf8')),validated};
}
/**
 * Never allow a semantic review to erase findings from the fail-only static
 * audit. All inputs are untrusted even after structural verification.
 *
 * A completed, independently authenticated engine and provenance witness are
 * still mandatory; absence of blockers remains INCONCLUSIVE. The returned
 * bytes may contain private model findings: NEVER output in PUBLIC CI/logs.
 *
 * This merges only the report data; it does not implement a second reviewer,
 * scheduler, decision authority, GitHub writer, or signed provenance ledger.
 */
export function combineReviewerFindings({
  staticReportBytes,semanticReportBytes,changedPaths
}={}){
  const a=parseReport(staticReportBytes,changedPaths);
  const b=parseReport(semanticReportBytes,changedPaths);
  if(a.value.run_id!==b.value.run_id)
    deny('COMBINED_REVIEW_RUN_MISMATCH');
  const fingerprints=new Map();
  for(const finding of [...a.value.findings,...b.value.findings]){
    const seen=fingerprints.get(finding.fingerprint);
    const canonical=canonicalJson(finding);
    if(seen!==undefined && seen!==canonical)
      deny('COMBINED_REVIEW_FINDING_CONFLICT');
    fingerprints.set(finding.fingerprint,canonical);
  }
  const combined=[...fingerprints.values()]
    .map(value=>JSON.parse(value))
    .sort((x,y)=>x.fingerprint.localeCompare(y.fingerprint,'en'));
  if(combined.length>50)deny('COMBINED_REVIEW_TOO_MANY_FINDINGS');
  const joined=[
    'Static security audit: '+a.value.summary,
    'Independent semantic analysis claim: '+b.value.summary
  ].join(' | ');
  if(joined.length>2000)deny('COMBINED_REVIEW_SUMMARY_TOO_LONG');
  const reportBytes=Buffer.from(canonicalJson({
    schema:'devfactory.reviewer-b.findings.v1',
    run_id:a.value.run_id,
    summary:joined,
    findings:combined
  }));
  const result=validateReviewerFindings({reportBytes,changedPaths});
  return Object.freeze({
    reportBytes,
    runId:a.value.run_id,
    provisionalState:result.provisionalState,
    blockingFindings:result.blockingFindingCount,
    findingCount:result.parsedFindingCount,
    // Even zero findings can never automatically authorize approval.
    independentReviewVerified:false,
    approvalAuthorized:false,
    publishEvent:null
  });
}
