import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { deriveAddedLinesFromDiff,isAddedLine } from './diff-added-lines.mjs';
import { canonicalJson } from '../src/canonical.mjs';
import { normalizeUntrustedModelFindings,prepareBoundedSemanticReview }
  from './semantic-review-request.mjs';

// Dormant, pure Ollama adapter. No network, no tokens, no inference and no POST.
// Inspired by MIT-licensed The-PR-Agent/pr-agent, without copying its source.
const MODELS=Object.freeze(['qwen2.5-coder:1.5b','qwen2.5-coder:7b','qwen2.5-coder:14b','qwen3:8b']);
const SHA40=/^[0-9a-f]{40}$/, HASH=/^[0-9a-f]{64}$/;
const RUN=/^[A-Za-z0-9_:-]{8,180}$/;
// Ollama supports strict JSON-schema structured output on /api/chat.
const FINDINGS_FORMAT=Object.freeze({
  type:'object',additionalProperties:false,
  required:['summary','findings'],
  properties:{
    summary:{type:'string',maxLength:2000},
    findings:{type:'array',maxItems:50,items:{
      type:'object',additionalProperties:false,
      required:['severity','path','line','message','evidence'],
      properties:{
        severity:{type:'string',enum:['critical','high','medium','low','informational']},
        path:{type:'string',maxLength:300},
        line:{type:'integer',minimum:1,maximum:1000000},
        message:{type:'string',minLength:1,maxLength:500},
        evidence:{type:'string',minLength:1,maxLength:1000}
      }
    }}
  }
});
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
  // Rebuild the plan from its exact diff: no caller-provided system prompt
  // or changed-path list is trusted merely because it has the right fields.
  const rebuilt=prepareBoundedSemanticReview({
    snapshot:{
      repository:s.repository,repository_id:1282086207,
      pr_number:s.prNumber,head_sha:s.headSha,base_sha:s.baseSha,
      diff_sha256:s.diffSha256
    },
    rawDiffBytes:Buffer.from(plan.privateDiffText,'utf8')
  });
  if(rebuilt.systemInstructions!==plan.systemInstructions ||
    JSON.stringify(rebuilt.changedPaths)!==JSON.stringify(plan.changedPaths))
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
  const reviewSchema=structuredClone(FINDINGS_FORMAT);
  // Force the model to use exact, GitHub-bound changed paths.
  reviewSchema.properties.findings.items.properties.path.enum=[...plan.changedPaths];
  const system=plan.systemInstructions.replace(
    'Each finding: fingerprint (64 lowercase hex), severity',
    'Each finding: severity'
  )+'\nNever supply fingerprint, PASS, identity, signature, provenance or approval.'+
    '\nReport only concrete newly introduced bugs proven by added diff lines.'+
    '\nUse only exact changed_paths names and new-side line numbers.'+
    '\nNo stylistic or speculative findings; write one-line message and evidence.'+
    '\nDiff snippets are not full files: omitted surrounding code and configuration may already exist.'+
    '\nBefore reporting, name a concrete failing input, runtime path, or security bypass introduced by the change.'+
    '\nTrace the actual result of guards and comparisons; do not mistake defensive null handling for an authorization bypass.'+
    '\nFor each suspected bug, contrast one specific input: what BEFORE returns/throws and what AFTER returns/throws.'+
    '\nIf both behaviors are equivalent for that input, it is NOT an introduced regression: omit the finding.'+
    '\nFor boolean guards and equality/inequality, evaluate both matching and nonmatching values, then name which was incorrectly accepted or rejected.'+
    '\nFor threshold comparisons, test a boundary input admitted AFTER but rejected BEFORE; do not reverse the direction of the change.'+
    '\nTreat reduced GitHub permissions, additional null guards, defensive clamps and immutable objects as safe by default absent explicit failing requirements in this diff.'+
    '\nMissing context is not evidence of failure; never invent callers, invariants, or runtime mutations to justify a warning.'+
    '\nIf no reproducible regression is supported by the diff, return an empty findings array.';
  const input=JSON.stringify({
    repository:plan.exactScope.repository,pr_number:plan.exactScope.prNumber,
    head_sha:plan.exactScope.headSha,base_sha:plan.exactScope.baseSha,
    changed_paths:plan.changedPaths,untrusted_unified_diff:plan.privateDiffText
  });
  const privateRequest=JSON.stringify({
    model,stream:false,format:reviewSchema,keep_alive:0,
    ...(model==='qwen3:8b'?{think:false}:{}),
    options:{temperature:0,num_ctx:8192,num_predict:maxOutputTokens},
    messages:[{role:'system',content:system},{role:'user',content:input}]
  });
  // Safety first: Ollama may silently truncate prompts exceeding num_ctx.
  // Count the FULL UTF-8 request, even schema/control JSON bytes, as a
  // pessimistic upper bound on tokenizer input. Reserve all requested output
  // tokens plus 512 tokens for chat framing, and FAIL CLOSED if over budget.
  // This does not claim independent full-context proof at inference time.
  const conservativeInputBytes=Buffer.byteLength(privateRequest,'utf8');
  const remainingContext=8192-maxOutputTokens-512;
  if(remainingContext<1||conservativeInputBytes>remainingContext)
    deny('OLLAMA_CONTEXT_CAPACITY_UNVERIFIED');
  const result=({
    provider:'local-ollama-no-api-fee',model,
    repository:plan.exactScope.repository,prNumber:plan.exactScope.prNumber,
    headSha:plan.exactScope.headSha,baseSha:plan.exactScope.baseSha,
    diffSha256:plan.exactScope.diffSha256,
    changedFiles:plan.changedPaths.length,maxOutputTokens,
    modelContextCompletenessVerified:false,
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
  trustedDiffBytes,expectedDiffSha256,
  maxPromptTokens=8192,maxCompletionTokens=2048
}={}){
  if(!MODELS.includes(expectedModel)||!RUN.test(runId)||
    !Number.isSafeInteger(maxPromptTokens)||maxPromptTokens<1||
    maxPromptTokens>8192||
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
  // A completion accepted outside the advertised 8192-token window could
  // hide truncation. Independent worker provenance is STILL not established.
  // Reserve 512 tokens for chat framing, even when Ollama usage is misleading.
  if(response.prompt_eval_count>maxPromptTokens||
    response.eval_count>maxCompletionTokens||
    response.prompt_eval_count+response.eval_count+512>8192)
    deny('OLLAMA_CONTEXT_LIMIT_EXCEEDED');
  let parsed;
  try{parsed=JSON.parse(response.message.content);}
  catch{deny('OLLAMA_INVALID_JSON');}
  if(!exact(parsed,['summary','findings'])||
    typeof parsed.summary!=='string'||!Array.isArray(parsed.findings)||
    parsed.findings.length>50)deny('OLLAMA_FINDINGS_SCHEMA_INVALID');
  if(!Buffer.isBuffer(trustedDiffBytes)||
    !HASH.test(expectedDiffSha256)||
    digest(trustedDiffBytes)!==expectedDiffSha256)
    deny('OLLAMA_ADDED_LINE_SCOPE_UNVERIFIED');
  const anchors=deriveAddedLinesFromDiff({diffBytes:trustedDiffBytes});
  if(!Array.isArray(trustedChangedPaths)||
    JSON.stringify(Object.keys(anchors))!==JSON.stringify(trustedChangedPaths))
    deny('OLLAMA_ADDED_LINE_SCOPE_UNVERIFIED');
  const changed=new Set(trustedChangedPaths);
  const seen=new Set();
  // Normalize harmless layout whitespace, never drop a finding or guess data.
  // Other control characters, empty text and oversized evidence remain blocked.
  const normalizedText=(value,max,code)=>{
    if(typeof value!=='string')deny(code);
    const clean=value.replace(/[\t\r\n ]+/g,' ').trim();
    if(!clean.length||clean.length>max||
      /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(clean))deny(code);
    return clean;
  };
  const findings=[];
  for(const f of parsed.findings){
    if(!exact(f,['severity','path','line','message','evidence']))
      deny('OLLAMA_FINDINGS_SCHEMA_INVALID');
    if(!changed.has(f.path))deny('OLLAMA_FINDING_PATH_MISMATCH');
    if(!Number.isSafeInteger(f.line)||f.line<1||f.line>1000000)
      deny('OLLAMA_FINDING_LINE_INVALID');
    if(!isAddedLine({anchors,path:f.path,line:f.line}))
      deny('OLLAMA_FINDING_NOT_ADDED_LINE');
    if(!['critical','high','medium','low','informational'].includes(f.severity))
      deny('OLLAMA_FINDING_SEVERITY_INVALID');
    const normalized={
      ...f,
      message:normalizedText(f.message,500,'OLLAMA_FINDING_TEXT_INVALID'),
      evidence:normalizedText(f.evidence,1000,'OLLAMA_FINDING_TEXT_INVALID')
    };
    const fingerprint=digest(
      'devfactory.review-finding.v1\0'+canonicalJson(normalized));
    if(seen.has(fingerprint))deny('OLLAMA_FINDING_DUPLICATE');
    seen.add(fingerprint);
    findings.push({...normalized,fingerprint});
  }
  const summary=normalizedText(parsed.summary,2000,'OLLAMA_SUMMARY_TEXT_INVALID');
  const checked=normalizeUntrustedModelFindings({
    rawModelOutput:canonicalJson({summary,findings}),
    runId,trustedChangedPaths
  });
  const report=Buffer.from(checked.reportBytes);
  const safe={
    provisionalState:checked.provisionalState,findingCount:checked.findingCount,
    reportedPromptTokens:response.prompt_eval_count,
    reportedCompletionTokens:response.eval_count,
    modelProvenanceVerified:false,modelContextCompletenessVerified:false,
    independentReviewVerified:false,
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
