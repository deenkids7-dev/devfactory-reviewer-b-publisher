import { parseCanonicalEnvelope, verifySerializedAttestation } from './strict-envelope.mjs';
import { validateReviewerFindings } from './findings-contract.mjs';

function deny(code) { throw new Error(code); }

/**
 * Correlate a signed analysis claim with strictly validated findings bytes.
 *
 * All trust roots, GitHub target SHA/diff and changed file paths are supplied
 * by a trusted future runtime. This function cannot authenticate its caller.
 * The report is always BLOCKED/INCONCLUSIVE or a provisional FAIL; never PASS.
 */
export function verifyReviewEvidence({
  envelopeBytes, reportBytes, trustedKeys, trustedTarget,
  trustedChangedPaths, seenReviewIds, seenNonces, now
}) {
  const envelope=parseCanonicalEnvelope(envelopeBytes);
  const signed=verifySerializedAttestation({
    envelopeBytes, reportBytes, trustedKeys, trustedTarget,
    seenReviewIds, seenNonces, now
  });
  const findings=validateReviewerFindings({
    reportBytes, changedPaths:trustedChangedPaths
  });
  if (envelope.payload.review_id!==findings.runId) {
    deny('ANALYSIS_RUN_ID_MISMATCH');
  }
  if (envelope.payload.analysis.disposition==='PASS' &&
      findings.blockingFindingCount>0) {
    deny('SIGNED_PASS_CONTRADICTS_BLOCKING_FINDINGS');
  }
  if (envelope.payload.analysis.disposition==='FAIL' &&
      findings.blockingFindingCount===0) {
    deny('SIGNED_FAIL_MISSING_BLOCKER_EVIDENCE');
  }
  return Object.freeze({
    analysisRunId:findings.runId,
    attestationSha256:signed.attestationSha256,
    validatedFindingCount:findings.parsedFindingCount,
    blockingFindingCount:findings.blockingFindingCount,
    provisionalState:findings.provisionalState,
    signatureVerified:true,
    independenceVerified:false,
    approvalAuthorized:false
  });
}
