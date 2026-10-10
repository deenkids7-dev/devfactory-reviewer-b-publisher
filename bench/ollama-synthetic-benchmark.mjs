import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { runFailOnlyStaticDiffAudit } from '../candidate/fail-only-static-audit.mjs';
import { prepareBoundedSemanticReview } from '../candidate/semantic-review-request.mjs';
import {
  prepareOfflineOllamaCandidate,validateOfflineOllamaCompletion
} from '../candidate/ollama-offline-contract.mjs';
import { combineReviewerFindings } from '../candidate/combine-findings.mjs';

// BENCHMARK ONLY. Never reads repositories, env vars, secrets, or user files.
// An Ollama server MUST be local to an independently operated test worker.
const OLLAMA='http://127.0.0.1:11434/api/chat';
const RUN='synthetic-local-quality-benchmark-001';
const PATH='.github/workflows/fake-synthetic.yml';
const SHA=value=>createHash('sha256').update(value).digest('hex');
const FIXTURES=Object.freeze([
  Object.freeze({label:'static risky trigger',source:'on: [push, pull_request_target]',
    knownStaticBlocker:true}),
  Object.freeze({label:'ordinary read-only workflow',source:'contents: read',
    knownStaticBlocker:false})
]);
function deny(code){throw Error(code);}
function diff(source) {
  return Buffer.from('diff --git a/'+PATH+' b/'+PATH+'\n'+
    'index 1234567..abcdef0 100644\n--- a/'+PATH+'\n'+
    '+++ b/'+PATH+'\n@@ -1 +1 @@\n-name: original\n+'+source+'\n');
}
function planFor(bytes) {
  return prepareBoundedSemanticReview({
    snapshot:{
      repository:'deenkids7-dev/deenkids',repository_id:1282086207,
      pr_number:898,head_sha:'a'.repeat(40),base_sha:'b'.repeat(40),
      diff_sha256:SHA(bytes)
    },rawDiffBytes:bytes
  });
}
async function boundedJson(response) {
  if(response?.status!==200||response?.redirected!==false||
    response?.url!==OLLAMA||
    !/^application\/json(?:;|$)/i.test(response.headers?.get('content-type')||'')||
    !response.body?.getReader)deny('OLLAMA_BENCHMARK_HTTP_REJECTED');
  const reader=response.body.getReader();
  const chunks=[];let n=0;
  try {
    for(;;){
      const {done,value}=await reader.read();
      if(done)break;
      if(!(value instanceof Uint8Array))deny('OLLAMA_BENCHMARK_BAD_CHUNK');
      n+=value.length;
      if(n>128*1024)deny('OLLAMA_BENCHMARK_RESPONSE_OVERSIZED');
      chunks.push(Buffer.from(value));
    }
  }catch{deny('OLLAMA_BENCHMARK_READ_FAILED');}
  finally{reader.releaseLock();}
  const body=Buffer.concat(chunks,n);
  const raw=body.toString('utf8');
  if(!Buffer.from(raw).equals(body))deny('OLLAMA_BENCHMARK_ENCODING_INVALID');
  try{return JSON.parse(raw);}catch{deny('OLLAMA_BENCHMARK_INVALID_JSON');}
}
/**
 * Actually invokes a LOCAL model, but ONLY with synthetic public-safe samples.
 * Uses existing fail-closed review modules; NEVER grants independence or PASS.
 */
export async function runSyntheticLocalOllamaBenchmark({
  fetchImpl=fetch,model='qwen2.5-coder:7b'
}={}) {
  if(typeof fetchImpl!=='function')deny('OLLAMA_BENCHMARK_FETCH_MISSING');
  const cases=[];
  for(const fixture of FIXTURES){
    const bytes=diff(fixture.source);
    const plan=planFor(bytes);
    const candidate=prepareOfflineOllamaCandidate({
      plan,model,maxOutputTokens:model==='qwen2.5-coder:1.5b'?512:2048
    });
    const staticAudit=runFailOnlyStaticDiffAudit({diffBytes:bytes,runId:RUN});
    if((staticAudit.blockingFindings>0)!==fixture.knownStaticBlocker)
      deny('OLLAMA_BENCHMARK_STATIC_ORACLE_FAILED');
    let response;
    try{
      response=await fetchImpl(OLLAMA,{
        method:'POST',redirect:'error',cache:'no-store',
        signal:AbortSignal.timeout(180000),
        headers:{'Content-Type':'application/json',Accept:'application/json'},
        body:candidate.privateRequestJson
      });
    }catch{deny('OLLAMA_BENCHMARK_LOCAL_UNAVAILABLE');}
    const raw=await boundedJson(response);
    const completion=validateOfflineOllamaCompletion({
      response:raw,expectedModel:candidate.model,runId:RUN,
      trustedChangedPaths:plan.changedPaths,
      maxPromptTokens:8192,maxCompletionTokens:candidate.maxOutputTokens
    });
    const combined=combineReviewerFindings({
      staticReportBytes:staticAudit.reportBytes,
      semanticReportBytes:completion.privateCanonicalReportBytes,
      changedPaths:plan.changedPaths
    });
    if(fixture.knownStaticBlocker&&combined.provisionalState!=='FAIL')
      deny('OLLAMA_BENCHMARK_STATIC_FINDING_LOST');
    cases.push(Object.freeze({
      label:fixture.label,seededStaticBlocker:fixture.knownStaticBlocker,
      semanticFindingCount:completion.findingCount,
      combinedBlockingCount:combined.blockingFindings,
      provisionalState:combined.provisionalState,
      approvalAuthorized:false,independenceVerified:false
    }));
  }
  return Object.freeze({
    benchmark:'synthetic-local-ollama-v1',
    testsCompleted:cases.length,model,
    cases:Object.freeze(cases),
    independentReviewerProvenanceVerified:false,
    privateSourceReviewed:false,
    approvalAuthorized:false,publishEvent:null
  });
}
// This explicit, operator-run CLI only outputs aggregate synthetic metrics.
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href){
  try {
    if(process.argv.length>3 ||
      (process.argv[2] && process.argv[2]!=='--small-synthetic'))
      deny('OLLAMA_BENCHMARK_UNSUPPORTED_ARGUMENT');
    const model=process.argv[2]==='--small-synthetic'?
      'qwen2.5-coder:1.5b':'qwen2.5-coder:7b';
    const summary=await runSyntheticLocalOllamaBenchmark({model});
    process.stdout.write(JSON.stringify(summary)+'\n');
  }catch{
    process.stderr.write('LOCAL_SYNTHETIC_BENCHMARK_BLOCKED\n');
    process.exitCode=1;
  }
}
