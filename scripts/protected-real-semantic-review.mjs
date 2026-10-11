/**
 * Protected PRIVATE source analysis using a real local Ollama model.
 * Native output is COMMENTED only: NEVER APPROVE, HUMAN_GO, or MERGE_GO.
 * Only execute from approved Publisher main and protected GitHub environment.
 */
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {approvedReadOnlyExecutionContext} from './protected-private-read-entrypoint.mjs';
import {createReviewerBAppJwt,createScopedReviewerBInstallationToken}
 from '../candidate/github-app-auth.mjs';
import {runReadOnlyReviewPreflight} from '../candidate/private-review-preflight.mjs';
import {executeCompleteLocalSemanticReview} from '../candidate/semantic-bounded-shards.mjs';
import {readNativeReviews} from '../candidate/github-review-readback.mjs';
import {assessNativeReviewUniqueness} from '../candidate/native-review-uniqueness.mjs';
const REPO='deenkids7-dev/deenkids';
const PUB='devfactory-reviewer-trust/devfactory-reviewer-b-publisher';
const MODEL='qwen2.5-coder:7b',BOT_ID=340237276,BOT='devfactory-reviewer-b[bot]';
const SHA40=/^[0-9a-f]{40}$/,SHA64=/^[0-9a-f]{64}$/;
const WORKFLOW=PUB+'/.github/workflows/reviewer-b-private-semantic.yml@refs/heads/main';
const digest=x=>createHash('sha256').update(x).digest('hex');
function deny(code){throw Error(code);}
function fail(code){return Object.freeze({ok:false,code});}
function text(v,max){
 if(typeof v!=='string'||!v.trim()||v.length>max||
   /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(v))deny('REPORT_TEXT_UNSAFE');
 return v.replace(/[\r\n\t ]+/g,' ').trim().replace(/[@<>]/g,'_')
  .replace(/\x60/g,"'").replace(/&/g,'and');
}
export function canRunRealSemanticReview(env){
 return approvedReadOnlyExecutionContext(env) &&
   env.GITHUB_EVENT_NAME==='workflow_dispatch' &&
   env.GITHUB_WORKFLOW_REF===WORKFLOW &&
   env.REVIEWER_B_EXPECTED_MODEL===MODEL &&
   typeof env.REVIEWER_B_TARGET_PR==='string' &&
   /^[1-9][0-9]{0,9}$/.test(env.REVIEWER_B_TARGET_PR);
}
export function prepareRealSemanticComment({preflight,local,runId}={}){
 const t=preflight?.target,bytes=local?.privateCanonicalReportBytes;
 if(t?.repository!==REPO||t.repositoryId!==1282086207||
   !Number.isSafeInteger(t.prNumber)||t.prNumber<1||
   typeof t.headSha!=='string'||!SHA40.test(t.headSha)||
   typeof t.baseSha!=='string'||!SHA40.test(t.baseSha)||
   typeof t.diffSha256!=='string'||!SHA64.test(t.diffSha256)||
   typeof runId!=='string'||!/^gh-[1-9][0-9]{0,18}-[1-9][0-9]{0,18}$/.test(runId)||
   !['FAIL','INCONCLUSIVE'].includes(preflight.staticDisposition)||
   !Number.isSafeInteger(preflight.blockingFindings)||
   preflight.blockingFindings<0||
   (preflight.staticDisposition==='FAIL')!==(preflight.blockingFindings>0)||
   preflight.approvalAuthorized!==false||
   preflight.independentReviewVerified!==false||
   preflight.publishEvent!==null||
   local?.localModelExecuted!==true||local.model!==MODEL||
   !['FAIL','INCONCLUSIVE'].includes(local.provisionalState)||
   !Number.isSafeInteger(local.findingCount)||local.findingCount<0||
   local.rawByteCoverageProven!==true||local.originalDiffSha256!==t.diffSha256||
   !Number.isSafeInteger(local.processedShardCount)||local.processedShardCount<1||
   local.approvalAuthorized!==false||
   local.independentReviewVerified!==false||local.publishEvent!==null||
   typeof local.localResponseSha256!=='string'||!SHA64.test(local.localResponseSha256)||
   !Buffer.isBuffer(bytes)||bytes.length<40||bytes.length>16384)
    deny('REAL_SEMANTIC_PROOF_INVALID');
 let report;
 try{report=JSON.parse(bytes.toString('utf8'));}catch{deny('REPORT_JSON_INVALID');}
 if(report?.schema!=='devfactory.reviewer-b.findings.v1'||
   report.run_id!==runId||typeof report.summary!=='string'||
   !report.summary.trim()||report.summary.length>2000||
   !Array.isArray(report.findings)||
   report.findings.length!==local.findingCount||report.findings.length>50||
   (local.provisionalState==='FAIL'&&report.findings.length===0))
   deny('REAL_SEMANTIC_REPORT_MISMATCH');
 const paths=new Set(preflight.privateSemanticPlan?.changedPaths||[]);
 if(!paths.size)deny('REPORT_CHANGED_SCOPE_MISSING');
 const lines=report.findings.map(f=>{
   if(!f||typeof f!=='object'||Array.isArray(f)||
     typeof f.path!=='string'||!paths.has(f.path)||
     !Number.isSafeInteger(f.line)||f.line<1||
     typeof f.fingerprint!=='string'||!SHA64.test(f.fingerprint)||
     typeof f.severity!=='string'||
     !['critical','high','medium','low','informational'].includes(f.severity)||
     typeof f.message!=='string'||!f.message.trim()||f.message.length>500||
     typeof f.evidence!=='string'||!f.evidence.trim()||f.evidence.length>1000)
     deny('REPORT_FINDING_INVALID');
   return '- '+f.severity.toUpperCase()+' '+text(f.path,300)+
     ':'+f.line+' — '+text(f.message,500)+' (Evidence: '+text(f.evidence,1000)+')';
 });
 const reportSha=digest(bytes);
 const marker=digest(Buffer.from([t.prNumber,t.headSha,runId,reportSha].join(':'))).slice(0,32);
 const outcome=local.provisionalState==='FAIL'||preflight.staticDisposition==='FAIL'
   ? 'PROVISIONAL_FINDINGS':'INCONCLUSIVE';
 const body=[
   '<!-- devfactory-reviewer-b-semantic-comment:v1:'+marker+' -->',
   'Reviewer B real LOCAL Qwen analysis — COMMENT ONLY (not approved)',
   '', 'Result: '+outcome+'; NO automated PASS or merge authority.',
   'Model: '+MODEL,'Exact head: '+t.headSha,
   'Exact base: '+t.baseSha,
   'Private diff SHA-256: '+t.diffSha256,
   'Real local report SHA-256: '+reportSha,
   'Real local response SHA-256: '+local.localResponseSha256,
   'Protected run: '+runId,
   'Static blockers: '+preflight.blockingFindings,
   'Semantic findings: '+local.findingCount,
   'Full-diff local model parts completed: '+local.processedShardCount,'',
   'Model summary: '+text(report.summary,2000),'',
   ...lines,'',
   'Manual verification required. This native COMMENTED report has no independent',
   'attestation, reviewer PASS, HUMAN_GO, MERGE_GO or merge authorization.'
 ].join('\n');
 if(body.length>12000)deny('REPORT_BODY_TOO_LARGE');
 return Object.freeze({event:'COMMENT',body,prNumber:t.prNumber,
   headSha:t.headSha,evidenceClass:'NATIVE_SEMANTIC_COMMENT_ONLY',
   approvalAuthorized:false,independentReviewVerified:false});
}
async function readJson(response){
 if(typeof response?.body?.getReader!=='function')deny('NATIVE_REPLY_INVALID');
 const reader=response.body.getReader(),blocks=[];let count=0,done=false;
 try{for(;;){
   const item=await reader.read();
   if(item.done){done=true;break;}
   if(!(item.value instanceof Uint8Array))deny('NATIVE_REPLY_BAD_CHUNK');
   count+=item.value.byteLength;
   if(count>24576)deny('NATIVE_REPLY_TOO_LARGE');
   blocks.push(Buffer.from(item.value));
 }}finally{
   if(!done){try{Promise.resolve(reader.cancel()).catch(()=>{});}catch{}}
   reader.releaseLock();
 }
 const bytes=Buffer.concat(blocks,count),raw=bytes.toString('utf8');
 if(!Buffer.from(raw,'utf8').equals(bytes))deny('NATIVE_REPLY_BAD_ENCODING');
 try{return JSON.parse(raw);}catch{deny('NATIVE_REPLY_BAD_JSON');}
}
export async function publishRealSemanticComment({plan,readToken,writeToken,
 approvedProtectedPublication=false,fetchImpl=globalThis.fetch}={}){
 if(approvedProtectedPublication!==true||
   plan?.evidenceClass!=='NATIVE_SEMANTIC_COMMENT_ONLY'||
   plan.event!=='COMMENT'||plan.approvalAuthorized!==false||
   plan.independentReviewVerified!==false||
   !Number.isSafeInteger(plan.prNumber)||plan.prNumber<1||
   typeof plan.headSha!=='string'||!SHA40.test(plan.headSha)||
   typeof plan.body!=='string'||!plan.body.startsWith(
     '<!-- devfactory-reviewer-b-semantic-comment:v1:')||
   plan.body.length>12000)deny('SEMANTIC_PUBLISH_DENIED');
 if(typeof fetchImpl!=='function'||typeof readToken!=='string'||
   typeof writeToken!=='string'||readToken.length<15||writeToken.length<15||
   readToken===writeToken||/[^-_A-Za-z0-9.]/.test(readToken)||
   /[^-_A-Za-z0-9.]/.test(writeToken))deny('SEMANTIC_TOKENS_INVALID');
 const read=()=>readNativeReviews({prNumber:plan.prNumber,
   expectedHeadSha:plan.headSha,installationToken:readToken,fetchImpl});
 const before=await read();
 if(assessNativeReviewUniqueness({observed:before,prNumber:plan.prNumber,
   currentHeadSha:plan.headSha}).blocked)deny('SEMANTIC_ALREADY_REVIEWED');
 const url='https://api.github.com/repos/'+REPO+'/pulls/'+plan.prNumber+'/reviews';
 let response;
 try{response=await fetchImpl(url,{method:'POST',redirect:'error',
   cache:'no-store',signal:AbortSignal.timeout(15000),
   headers:{Authorization:'Bearer '+writeToken,Accept:'application/vnd.github+json',
    'Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28',
    'User-Agent':'devfactory-reviewer-b-local-semantic'},
   body:JSON.stringify({event:'COMMENT',commit_id:plan.headSha,body:plan.body})});
 }catch{deny('SEMANTIC_POST_FAILED');}
 if(![200,201].includes(response?.status)||response?.url!==url||
   response.redirected!==false||
   !/^application\/(?:vnd\.github\+)?json(?:\s*;|$)/i.test(
     response.headers?.get?.('content-type')||''))
     deny('SEMANTIC_POST_REJECTED');
 const created=await readJson(response);
 if(!Number.isSafeInteger(created?.id)||created.id<1||
   created.state!=='COMMENTED'||created.commit_id!==plan.headSha||
   created.body!==plan.body||created.user?.id!==BOT_ID||
   created.user?.login!==BOT||
   created.pull_request_url!=='https://api.github.com/repos/'+REPO+
     '/pulls/'+plan.prNumber)deny('SEMANTIC_POST_UNVERIFIED');
 const after=await read();
 const botReviews=after.reviews.filter(x=>x.user.id===BOT_ID||x.user.login===BOT);
 if(botReviews.filter(x=>x.commit_id===plan.headSha).length!==1||
   botReviews.filter(x=>x.id===created.id&&x.body===plan.body&&
     x.commit_id===plan.headSha&&x.state==='COMMENTED'&&
     x.user.id===BOT_ID&&x.user.login===BOT).length!==1)
   deny('SEMANTIC_READBACK_INVALID');
 return Object.freeze({ok:true,code:'REAL_REVIEW_COMMENT_VERIFIED',
   prNumber:plan.prNumber,reviewId:created.id,
   approvalAuthorized:false,independentReviewVerified:false});
}
export async function executeProtectedRealSemanticReview({
 env={},now=Date.now(),fetchImpl=globalThis.fetch,
 modelFetchImpl=globalThis.fetch}={}){
 if(!canRunRealSemanticReview(env))return fail('CONTEXT_DENIED');
 const pem=env.REVIEWER_B_GITHUB_APP_PRIVATE_KEY_PEM;
 if(typeof pem!=='string'||pem.length<100)
   return fail('CREDENTIAL_NOT_PROVISIONED');
 try{
   const runId='gh-'+env.GITHUB_RUN_ID+'-'+env.GITHUB_RUN_ATTEMPT;
   const jwt=createReviewerBAppJwt({privateKeyPem:pem,now});
   const read=await createScopedReviewerBInstallationToken({
     appJwt:jwt,purpose:'reviewRead',now,fetchImpl});
   const preflight=await runReadOnlyReviewPreflight({
     prNumber:Number(env.REVIEWER_B_TARGET_PR),
     runId,installationToken:read.token,fetchImpl});
   const local=await executeCompleteLocalSemanticReview({
     plan:preflight.privateSemanticPlan,runId,model:MODEL,
     fetchImpl:modelFetchImpl,maxOutputTokens:1024});
   const plan=prepareRealSemanticComment({preflight,local,runId});
   // LOCAL inference may run longer than the initial App JWT's 8-minute TTL.
   // Mint the purpose-separated WRITE token with a fresh App JWT only AFTER
   // the complete PRIVATE model report is validated. No bearer survives a retry.
   const writerNow=Date.now();
   const writerJwt=createReviewerBAppJwt({privateKeyPem:pem,now:writerNow});
   const writer=await createScopedReviewerBInstallationToken({
     appJwt:writerJwt,purpose:'publish',now:writerNow,fetchImpl});
   return await publishRealSemanticComment({plan,readToken:read.token,
     writeToken:writer.token,approvedProtectedPublication:true,fetchImpl});
 }catch{
   return fail('REAL_REVIEW_FAILED_CLOSED');
 }
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===resolve(process.argv[1])){
 try{
   const result=await executeProtectedRealSemanticReview({env:process.env});
   console.log('PROTECTED_REVIEW_'+result.code);
   if(!result.ok)process.exitCode=1;
 }catch{
   console.log('PROTECTED_REVIEW_FAILED_CLOSED');
   process.exitCode=1;
 }
}
