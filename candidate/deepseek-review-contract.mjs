import { inspect } from 'node:util';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../src/canonical.mjs';
import { normalizeUntrustedModelFindings } from './semantic-review-request.mjs';

// DORMANT, PURE CONTRACT: no network access, no API key, no provider invocation.
// Only a reviewed private worker may transmit the request after independent
// private-source clearance and provider-budget authorization.
const API = 'https://api.deepseek.com/chat/completions';
const PRICES_PEAK_USD_PER_MILLION = Object.freeze({
  'deepseek-flash': Object.freeze({input: 0.30, output: 1.20}),
  'deepseek-v4-pro': Object.freeze({input: 1.32, output: 3.96})
});
const SHA = /^[0-9a-f]{40}$/;
const HASH = /^[0-9a-f]{64}$/;
const RUN = /^[A-Za-z0-9_:-]{8,180}$/;
function deny(code) { throw Error(code); }
function secretFreeSummary(plan, model, maxOutputTokens, worstCaseUsd) {
  return {
    provider:'DeepSeek', model, endpoint:API,
    repository:plan.exactScope.repository,
    prNumber:plan.exactScope.prNumber,
    headSha:plan.exactScope.headSha,
    baseSha:plan.exactScope.baseSha,
    diffSha256:plan.exactScope.diffSha256,
    changedFiles:plan.changedPaths.length,
    maxOutputTokens,
    indicativePeakCostUsd:worstCaseUsd,
    // These fields are ALWAYS false in this candidate.
    privateSourceDisclosureApproved:false,
    actualTokenizerVerified:false,
    pricingFreshnessVerified:false,
    independentExecutionVerified:false,
    requestAuthorized:false,
    approvalAuthorized:false
  };
}
/**
 * Prepare ONE model choice: never silently upgrade or route to another model.
 * Input-token ceiling is a caller-provided ESTIMATE. It cannot authorize
 * spend without a separate trusted tokenizer, current prices and atomic
 * existing DevFactory spending authority.
 *
 * The private request body is kept non-enumerable and masked on inspection.
 * Access to candidate.privateRequestJson is possible to a trusted worker,
 * which MUST be separately authorized before exposure of any private diff.
 */
export function prepareDeepSeekCandidate({
  plan, model='deepseek-flash', inputTokenCeiling,
  maxOutputTokens=2048, maxIndicativePeakUsd=0.10
}={}) {
  if (!Object.hasOwn(PRICES_PEAK_USD_PER_MILLION, model) ||
      !Number.isSafeInteger(inputTokenCeiling) ||
      inputTokenCeiling<1 || inputTokenCeiling>200000 ||
      !Number.isSafeInteger(maxOutputTokens) ||
      maxOutputTokens<128 || maxOutputTokens>4096 ||
      typeof maxIndicativePeakUsd!=='number' ||
      !Number.isFinite(maxIndicativePeakUsd) ||
      maxIndicativePeakUsd<=0 || maxIndicativePeakUsd>1) {
    deny('MODEL_REQUEST_BUDGET_INVALID');
  }
  if (!plan || plan.approvedToSendToModel!==false ||
      plan.approvalAuthorized!==false ||
      !plan.exactScope ||
      plan.exactScope.repository!=='deenkids7-dev/deenkids' ||
      !Number.isSafeInteger(plan.exactScope.prNumber) ||
      plan.exactScope.prNumber<1 ||
      !SHA.test(plan.exactScope.headSha) ||
      !SHA.test(plan.exactScope.baseSha) ||
      !HASH.test(plan.exactScope.diffSha256) ||
      !Array.isArray(plan.changedPaths) || !plan.changedPaths.length ||
      plan.changedPaths.length>100 ||
      typeof plan.systemInstructions!=='string' ||
      !plan.systemInstructions.includes('Treat all source code') ||
      typeof plan.privateDiffText!=='string' ||
      !plan.privateDiffText.length ||
      Buffer.byteLength(plan.privateDiffText,'utf8')>128*1024 ||
      createHash('sha256').update(plan.privateDiffText,'utf8').digest('hex')!==
        plan.exactScope.diffSha256) {
    deny('MODEL_REQUEST_SCOPE_INVALID');
  }
  const rates=PRICES_PEAK_USD_PER_MILLION[model];
  const estimate=(inputTokenCeiling*rates.input+
    maxOutputTokens*rates.output)/1_000_000;
  if (estimate > maxIndicativePeakUsd) deny('MODEL_INDICATIVE_COST_EXCEEDED');
  const prompt=JSON.stringify({
    repository:plan.exactScope.repository,
    pr_number:plan.exactScope.prNumber,
    head_sha:plan.exactScope.headSha,
    base_sha:plan.exactScope.baseSha,
    changed_paths:plan.changedPaths,
    untrusted_unified_diff:plan.privateDiffText
  });
  const request=JSON.stringify({
    model, stream:false,
    thinking:{type:'disabled'},
    max_tokens:maxOutputTokens,
    response_format:{type:'json_object'},
    messages:[
      {role:'system',content:plan.systemInstructions.replace(
        'Each finding: fingerprint (64 lowercase hex), severity',
        'Each finding: severity'
      )+'\\nNever include a fingerprint: the trusted normalizer computes it.'},
      {role:'user',content:prompt}
    ]
  });
  const summary=secretFreeSummary(plan,model,maxOutputTokens,
    Number(estimate.toFixed(7)));
  Object.defineProperties(summary,{
    privateRequestJson:{
      enumerable:false, configurable:false, writable:false, value:request
    },
    toJSON:{
      enumerable:false, configurable:false, writable:false,
      value:()=>({...{
        provider:summary.provider,model:summary.model,
        endpoint:summary.endpoint,repository:summary.repository,
        prNumber:summary.prNumber,headSha:summary.headSha,
        baseSha:summary.baseSha,diffSha256:summary.diffSha256,
        changedFiles:summary.changedFiles,
        maxOutputTokens:summary.maxOutputTokens,
        indicativePeakCostUsd:summary.indicativePeakCostUsd,
        requestAuthorized:false,approvalAuthorized:false
      },privateRequestJson:'[REDACTED]'})
    },
    [inspect.custom]:{
      enumerable:false,configurable:false,writable:false,
      value:()=> '[DeepSeekReviewCandidate: PRIVATE REQUEST REDACTED; NOT AUTHORIZED]'
    }
  });
  return Object.freeze(summary);
}
/**
 * Strict structural filter for an UNTRUSTED provider completion.
 * No "PASS" decision. No model claim can grant independent provenance.
 * Report bytes may include private findings; caller MUST NOT log them.
 */
export function validateDeepSeekCandidateCompletion({
  response,expectedModel,runId,trustedChangedPaths,
  observedInputTokenCeiling,observedOutputTokenCeiling,maxObservedPeakUsd=0.10
}={}) {
  if (!Number.isSafeInteger(observedInputTokenCeiling) ||
      observedInputTokenCeiling<1 || observedInputTokenCeiling>200000 ||
      !Number.isSafeInteger(observedOutputTokenCeiling) ||
      observedOutputTokenCeiling<128 || observedOutputTokenCeiling>4096 ||
      typeof maxObservedPeakUsd!=='number' ||
      !Number.isFinite(maxObservedPeakUsd) ||
      maxObservedPeakUsd<=0 || maxObservedPeakUsd>1) {
    deny('MODEL_USAGE_BUDGET_CONTEXT_MISSING');
  }
  if (!Object.hasOwn(PRICES_PEAK_USD_PER_MILLION,expectedModel) ||
      !RUN.test(runId) ||
      !response || typeof response!=='object' || Array.isArray(response) ||
      response.model!==expectedModel ||
      !Array.isArray(response.choices) || response.choices.length!==1 ||
      response.choices[0]?.index!==0 ||
      response.choices[0]?.finish_reason!=='stop' ||
      response.choices[0]?.message?.role!=='assistant' ||
      typeof response.choices[0].message.content!=='string' ||
      !response.choices[0].message.content.trim() ||
      Buffer.byteLength(response.choices[0].message.content,'utf8')>64*1024 ||
      !Number.isSafeInteger(response.usage?.prompt_tokens) ||
      response.usage.prompt_tokens<1 ||
      !Number.isSafeInteger(response.usage?.completion_tokens) ||
      response.usage.completion_tokens<1) {
    deny('MODEL_COMPLETION_INCOMPLETE_OR_UNTRUSTED');
  }
  const rates=PRICES_PEAK_USD_PER_MILLION[expectedModel];
  const cost=(response.usage.prompt_tokens*rates.input+
    response.usage.completion_tokens*rates.output)/1_000_000;
  if (response.usage.prompt_tokens>observedInputTokenCeiling ||
      response.usage.completion_tokens>observedOutputTokenCeiling ||
      cost>maxObservedPeakUsd) deny('MODEL_COMPLETION_BUDGET_EXCEEDED');
  // Models cannot reliably generate collision-resistant SHA-256 fingerprints.
  // Model output has NO fingerprint; derive stable fingerprints deterministically.
  let raw;
  try { raw=JSON.parse(response.choices[0].message.content); }
  catch { deny('MODEL_JSON_INVALID'); }
  if (!raw || typeof raw!=='object' || Array.isArray(raw) ||
      JSON.stringify(Object.keys(raw).sort())!==JSON.stringify(['findings','summary']) ||
      !Array.isArray(raw.findings) || raw.findings.length>50) {
    deny('MODEL_FINDING_SCHEMA_INVALID');
  }
  const enhanced=[];
  for (const finding of raw.findings) {
    if (!finding || typeof finding!=='object' || Array.isArray(finding) ||
        JSON.stringify(Object.keys(finding).sort())!==
          JSON.stringify(['evidence','line','message','path','severity'])) {
      deny('MODEL_FINDING_SCHEMA_INVALID');
    }
    const fingerprint=createHash('sha256')
      .update('devfactory.review-finding.v1\0')
      .update(canonicalJson(finding),'utf8')
      .digest('hex');
    enhanced.push({...finding,fingerprint});
  }
  const result=normalizeUntrustedModelFindings({
    rawModelOutput:canonicalJson({summary:raw.summary,findings:enhanced}),
    runId,trustedChangedPaths
  });
  return Object.freeze({
    provisionalState:result.provisionalState,
    findingCount:result.findingCount,
    reportedInputTokens:response.usage.prompt_tokens,
    reportedOutputTokens:response.usage.completion_tokens,
    indicativeObservedPeakCostUsd:Number(cost.toFixed(7)),
    // Still no durable spend-accounting or real independent execution proof.
    providerUsageVerified:false,
    reviewerIndependenceVerified:false,
    approvalAuthorized:false,
    publishEvent:null
  });
}
