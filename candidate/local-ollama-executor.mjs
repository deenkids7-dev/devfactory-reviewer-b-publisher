import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { prepareOfflineOllamaCandidate, validateOfflineOllamaCompletion }
  from './ollama-offline-contract.mjs';

// PROSPECTIVE LOCAL-only inference transport. Never enabled by public PR CI,
// and never authorizes release or a native GitHub review. Exact loopback URL
// prevents sending PRIVATE code to an external model API by configuration.
const LOCAL_URL='http://127.0.0.1:11434/api/chat';
const JSON_TYPE=/^application\/json(?:\s*;|$)/i;
const MAX_RESPONSE_BYTES=256*1024;
function deny(code){throw Error(code);}
async function consumeBounded(response){
  if(!response?.body?.getReader)deny('LOCAL_MODEL_BODY_INVALID');
  const reader=response.body.getReader();
  let count=0,done=false;const chunks=[];
  try{
    for(;;){
      const part=await reader.read();
      if(part.done){done=true;break;}
      if(!(part.value instanceof Uint8Array))
        deny('LOCAL_MODEL_CHUNK_INVALID');
      count+=part.value.byteLength;
      if(count>MAX_RESPONSE_BYTES)deny('LOCAL_MODEL_RESPONSE_OVERSIZED');
      chunks.push(Buffer.from(part.value));
    }
  }finally{
    if(!done){try{await reader.cancel();}catch{/* preserve denial */}}
    reader.releaseLock();
  }
  return Buffer.concat(chunks,count);
}
/**
 * A bounded local inference ONLY after a separately reviewed protected
 * environment has obtained a consistent private snapshot and authorized
 * LOCAL processing. Caller must never derive the authorization boolean
 * from untrusted PR text, model output, or a workflow_dispatch input.
 *
 * No App credentials, cloud API, source logging, native review write,
 * source attestation or autonomous PASS. Even a clean response is
 * INCONCLUSIVE; independent trust evidence must be established elsewhere.
 */
export async function executeLocalOllamaReview({
  plan,trustedDiffBytes,runId,model='qwen2.5-coder:7b',
  approvedLocalPrivateProcessing=false,fetchImpl=globalThis.fetch,
  maxOutputTokens=2048
}={}){
  if(approvedLocalPrivateProcessing!==true)
    deny('LOCAL_PRIVATE_PROCESSING_NOT_AUTHORIZED');
  if(typeof fetchImpl!=='function'||!Buffer.isBuffer(trustedDiffBytes))
    deny('LOCAL_MODEL_INPUT_UNVERIFIED');
  const req=prepareOfflineOllamaCandidate({
    plan,model,maxOutputTokens
  });
  const digest=createHash('sha256').update(trustedDiffBytes).digest('hex');
  if(digest!==req.diffSha256||
     trustedDiffBytes.toString('utf8')!==plan.privateDiffText)
    deny('LOCAL_MODEL_DIFF_SCOPE_MISMATCH');
  let response;
  try{
    response=await fetchImpl(LOCAL_URL,{
      method:'POST',redirect:'error',cache:'no-store',
      signal:AbortSignal.timeout(90000),
      headers:{'Content-Type':'application/json','Accept':'application/json'},
      body:req.privateRequestJson
    });
  }catch{deny('LOCAL_MODEL_REQUEST_FAILED');}
  if(response?.status!==200||response.redirected!==false||
     response.url!==LOCAL_URL||
     !JSON_TYPE.test(response.headers?.get('content-type')||''))
    deny('LOCAL_MODEL_ENDPOINT_UNVERIFIED');
  const length=response.headers?.get('content-length');
  if(length!==null&&length!==undefined&&length!==''&&
     (!/^\d+$/.test(length)||Number(length)>MAX_RESPONSE_BYTES))
    deny('LOCAL_MODEL_RESPONSE_OVERSIZED');
  let bytes;
  try{bytes=await consumeBounded(response);}
  catch{deny('LOCAL_MODEL_RESPONSE_REJECTED');}
  const raw=bytes.toString('utf8');
  if(!Buffer.from(raw,'utf8').equals(bytes))
    deny('LOCAL_MODEL_ENCODING_INVALID');
  let body;
  try{body=JSON.parse(raw);}
  catch{deny('LOCAL_MODEL_INVALID_JSON');}
  const checked=validateOfflineOllamaCompletion({
    response:body,expectedModel:model,runId,
    trustedChangedPaths:plan.changedPaths,
    trustedDiffBytes,expectedDiffSha256:digest,
    maxCompletionTokens:maxOutputTokens
  });
  const privateReport=Buffer.from(checked.privateCanonicalReportBytes);
  const result={
    model,localModelExecuted:true,
    provisionalState:checked.provisionalState,
    findingCount:checked.findingCount,
    localResponseSha256:createHash('sha256').update(bytes).digest('hex'),
    modelContextCompletenessVerified:false,
    modelProvenanceVerified:false,
    independentReviewVerified:false,
    approvalAuthorized:false,publishEvent:null
  };
  Object.defineProperties(result,{
    privateCanonicalReportBytes:{enumerable:false,configurable:false,
      get:()=>Buffer.from(privateReport)},
    toJSON:{enumerable:false,configurable:false,
      value:()=>({...Object.fromEntries(Object.entries(result)),
        privateCanonicalReportBytes:'[REDACTED_PRIVATE_REPORT]'})},
    [inspect.custom]:{enumerable:false,configurable:false,
      value:()=> '[LocalOllamaReview: PRIVATE REPORT REDACTED; NOT VERIFIED]'}
  });
  return Object.freeze(result);
}
