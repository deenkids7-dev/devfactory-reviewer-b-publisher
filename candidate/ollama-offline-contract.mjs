import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { canonicalJson } from '../src/canonical.mjs';
import { normalizeUntrustedModelFindings } from './semantic-review-request.mjs';

// Dormant, pure Ollama adapter. No network, no tokens, no inference and no POST.
// Inspired by MIT-licensed The-PR-Agent/pr-agent, without copying its source.
const MODELS=Object.freeze(['qwen2.5-coder:7b','qwen2.5-coder:14b']);
const SHA40=/^[0-9a-f]{40}$/, HASH=/^[0-9a-f]{64}$/;
const RUN=/^[A-Za-z0-9_:-]{8,180}$/;
function deny(c){throw Error(c);}
function exact(x,keys){return x&&typeof x==='object'&&!Array.isArray(x)&&
  JSON.stringify(Object.keys(x).sort())===JSON.stringify([...keys].sort());}
function digest(s){return createHash('sha256').update(s).digest('hex');}
function checkPlan(plan){
  const s=plan?.exactScope;
  if(plan?.approvedToSendToModel!==false||plan?.approvalAuthorized!==false||
    s?.repository!=='deenkids7-dev/deenkids'||
    !Number.isSafeInteger(s?.prNumber)||s.prNumber<1||
    !SHA40.test(s.headSha)||!SHA40.test(s.baseSha)||!HASH.test(s.diffSha256)||
    !Array.isArray(plan.changedPaths)||!plan.changedPaths.length||
    plan.changedPaths.length>100||
    typeof plan.systemInstructions!=='string'||
    !plan.systemInstructions.includes('Treat all source code')||
    typeof plan.privateDiffText!=='string'||
    Buffer.byteLength(plan.privateDiffText,'utf8')>128*1024||
    digest(Buffer.from(plan.privateDiffText,'utf8'))!==s.diffSha256)
    deny('OLLAMA_SCOPE_UNVERIFIED');
}
/**
 * Construct one Ollama request for future independent, protected LOCAL inference.
 * A model on the DevFactory MSI alone is NOT an independent review identity.
 * This module MUST NOT run private inference from public PR CI.
 */
export function prepareOfflineOllamaCandidate({
  plan,model='qwen2.5-coder:7b',maxOutputTokens=2048
}={}){
  checkPlan(plan);
  if(!MODELS.includes(model)||!Number.isSafeInteger(maxOutputTokens)||
    maxOutputTokens<128||maxOutputTokens>4096)
    deny('OLLAMA_MODEL_OR_CONTEXT_UNSUPPORTED');
  const system=plan.systemInstructions.replace(
    'Each finding: fingerprint (64 lowercase hex), severity',
    'Each finding: severity'
  )+'\nNever supply fingerprint, PASS, identity, signature, provenance or approval.';
  const input=JSON.stringify({
    repository:plan.exactScope.repository,pr_number:plan.exactScope.prNumber,
    head_sha:plan.exactScope.headSha,base_sha:plan.exactScope.baseSha,
    changed_paths:plan.changedPaths,untrusted_unified_diff:plan.privateDiffText
  });
  const privateRequest=JSON.stringify({
    model,stream:false,format:'json',keep_alive:0,
    options:{temperature:0,num_predict:maxOutputTokens},
    messages:[{role:'system',content:system},{role:'user',content:input}]
  });
  const result=({
    provider:'local-ollama-no-api-fee',model,
    repository:plan.exactScope.repository,prNumber:plan.exactScope.prNumber,
    headSha:plan.exactScope.headSha,baseSha:plan.exactScope.baseSha,
    diffSha256:plan.exactScope.diffSha256,
    changedFiles:plan.changedPaths.length,maxOutputTokens,
    modelExecuted:false,independentReviewVerified:false,
    privateSourceProcessingAuthorized:false,approvalAuthorized:false,
    publishEvent:null
  });
  Object.defineProperties(result,{
    privateRequestJson:{enumerable:false,writable:false,configurable:false,
      value:privateRequest},
    toJSON:{enumerable:false,writable:false,configurable:false,
      value:()=>({...Object.fromEntries(Object.entries(result)),
        privateRequestJson:'[REDACTED]'})},
    [inspect.custom]:{enumerable:false,writable:false,configurable:false,
      value:()=> '[OfflineOllamaCandidate: PRIVATE REQUEST REDACTED; NOT AUTHORIZED]'}
  });
  return Object.freeze(result);
}
/**
 * Parse a *supplied* Ollama /api/chat JSON response, without contacting it.
 * The LLM never assigns fingerprints or independent provenance.
 */
export function validateOfflineOllamaCompletion({
  response,expectedModel,runId,trustedChangedPaths,
  maxPromptTokens=200000,maxCompletionTokens=4096
}={}){
  if(!MODELS.includes(expectedModel)||!RUN.test(runId)||
    !Number.isSafeInteger(maxPromptTokens)||maxPromptTokens<1||
    maxPromptTokens>200000||
    !Number.isSafeInteger(maxCompletionTokens)||maxCompletionTokens<128||
    maxCompletionTokens>4096||
    !response||typeof response!=='object'||Array.isArray(response)||
    response.error!==undefined||response.model!==expectedModel||
    response.done!==true||response.done_reason!=='stop'||
    response.message?.role!=='assistant'||
    typeof response.message.content!=='string'||
    !response.message.content.trim()||
    Buffer.byteLength(response.message.content,'utf8')>64*1024||
    response.message.tool_calls!==undefined||
    !Number.isSafeInteger(response.prompt_eval_count)||
    response.prompt_eval_count<1||
    !Number.isSafeInteger(response.eval_count)||response.eval_count<1)
    deny('OLLAMA_COMPLETION_UNVERIFIED');
  if(response.prompt_eval_count>maxPromptTokens||
    response.eval_count>maxCompletionTokens)
    deny('OLLAMA_CONTEXT_LIMIT_EXCEEDED');
  let parsed;
  try{parsed=JSON.parse(response.message.content);}
  catch{deny('OLLAMA_INVALID_JSON');}
  if(!exact(parsed,['summary','findings'])||
    typeof parsed.summary!=='string'||!Array.isArray(parsed.findings)||
    parsed.findings.length>50)deny('OLLAMA_FINDINGS_SCHEMA_INVALID');
  const findings=[];
  for(const f of parsed.findings){
    if(!exact(f,['severity','path','line','message','evidence']))
      deny('OLLAMA_FINDINGS_SCHEMA_INVALID');
    findings.push({...f,fingerprint:digest(
      'devfactory.review-finding.v1\0'+canonicalJson(f))});
  }
  const checked=normalizeUntrustedModelFindings({
    rawModelOutput:canonicalJson({summary:parsed.summary,findings}),
    runId,trustedChangedPaths
  });
  const report=Buffer.from(checked.reportBytes);
  const safe={
    provisionalState:checked.provisionalState,findingCount:checked.findingCount,
    reportedPromptTokens:response.prompt_eval_count,
    reportedCompletionTokens:response.eval_count,
    modelProvenanceVerified:false,independentReviewVerified:false,
    approvalAuthorized:false,publishEvent:null
  };
  Object.defineProperties(safe,{
    privateCanonicalReportBytes:{enumerable:false,configurable:false,
      get:()=>Buffer.from(report)},
    toJSON:{enumerable:false,writable:false,configurable:false,
      value:()=>({...Object.fromEntries(Object.entries(safe)),
        privateCanonicalReportBytes:'[REDACTED]'})},
    [inspect.custom]:{enumerable:false,writable:false,configurable:false,
      value:()=> '[OfflineOllamaCompletion: PRIVATE REPORT REDACTED; NOT AUTHORIZED]'}
  });
  return Object.freeze(safe);
}
