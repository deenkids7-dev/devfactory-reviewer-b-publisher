// Reviewer output structure validation only. No AI provider call, no
// GitHub access, no producer keys and no approval decision.
const MAX_REPORT_BYTES = 64 * 1024;
const MAX_FINDINGS = 50;
const PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)*$/;
const RUN_ID = /^[A-Za-z0-9_:-]{8,180}$/;
const HASH = /^[0-9a-f]{64}$/;
const SEVERITIES = new Set(['critical','high','medium','low','informational']);

function deny(code) { throw new Error(code); }
function fields(obj, expected) {
  return obj !== null && typeof obj === 'object' && !Array.isArray(obj) &&
    JSON.stringify(Object.keys(obj).sort())===JSON.stringify([...expected].sort());
}
function text(value, min, max) {
  return typeof value === 'string' && value.length>=min &&
    value.length<=max && !/[\x00-\x08\x0e-\x1f]/.test(value);
}

/**
 * Every accepted report remains INCONCLUSIVE or FAIL. An LLM-provided PASS or
 * an empty findings list is never a trustworthy independent review verdict.
 *
 * Changed file paths MUST come from an independently verified GitHub diff,
 * not from the output of the reviewer engine or PR author.
 */
export function validateReviewerFindings({reportBytes,changedPaths}) {
  if (!Buffer.isBuffer(reportBytes) || reportBytes.length<2 ||
      reportBytes.length>MAX_REPORT_BYTES ||
      !Array.isArray(changedPaths) || changedPaths.length<1 ||
      changedPaths.length>100 || changedPaths.some(p=>typeof p!=='string'||!PATH.test(p))) {
    deny('REVIEW_INPUT_UNTRUSTED');
  }
  const raw=reportBytes.toString('utf8');
  if (!Buffer.from(raw,'utf8').equals(reportBytes)) deny('REVIEW_INVALID_UTF8');
  let value;
  try { value=JSON.parse(raw); } catch { deny('REVIEW_INVALID_JSON'); }
  if (!fields(value,['schema','run_id','summary','findings']) ||
      value.schema!=='devfactory.reviewer-b.findings.v1' ||
      !RUN_ID.test(value.run_id) ||
      !text(value.summary,1,2000) ||
      !Array.isArray(value.findings) || value.findings.length>MAX_FINDINGS) {
    deny('REVIEW_INVALID_FIELDS');
  }
  const changed=new Set(changedPaths);
  const seen=new Set();
  for(const finding of value.findings){
    if (!fields(finding,['fingerprint','severity','path','line','message','evidence']) ||
        !HASH.test(finding.fingerprint) ||
        !SEVERITIES.has(finding.severity) ||
        !PATH.test(finding.path) || !changed.has(finding.path) ||
        !Number.isSafeInteger(finding.line) || finding.line<1 || finding.line>1_000_000 ||
        !text(finding.message,1,500) || !text(finding.evidence,1,1000) ||
        seen.has(finding.fingerprint)) {
      deny('REVIEW_FINDING_INVALID');
    }
    seen.add(finding.fingerprint);
  }
  const blocking=value.findings.filter(f=>
    f.severity==='critical'||f.severity==='high');
  return Object.freeze({
    parsedFindingCount:value.findings.length,
    blockingFindingCount:blocking.length,
    provisionalState:blocking.length>0?'FAIL':'INCONCLUSIVE',
    independenceVerified:false,
    approvalAuthorized:false
  });
}
