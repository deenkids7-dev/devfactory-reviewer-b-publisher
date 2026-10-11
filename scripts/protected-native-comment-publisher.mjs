import {readNativeReviews} from '../candidate/github-review-readback.mjs';
import {assessNativeReviewUniqueness} from '../candidate/native-review-uniqueness.mjs';
import {prepareNonAuthorizingNativeComment} from '../candidate/native-comment-contract.mjs';
const REPO='deenkids7-dev/deenkids';
const BOT_ID=340237276,BOT_LOGIN='devfactory-reviewer-b[bot]';
const RESP_LIMIT=16*1024;
function deny(code){throw Error(code);}
async function boundedResponse(response){
  if(typeof response?.body?.getReader!=='function')
    deny('NATIVE_COMMENT_UNREADABLE_RESPONSE');
  const reader=response.body.getReader();const blocks=[];let count=0,complete=false;
  try{
    for(;;){
      const {done,value}=await reader.read();
      if(done){complete=true;break;}
      if(!(value instanceof Uint8Array))deny('NATIVE_COMMENT_BAD_CHUNK');
      count+=value.byteLength;
      if(count>RESP_LIMIT)deny('NATIVE_COMMENT_RESPONSE_OVERSIZED');
      blocks.push(Buffer.from(value));
    }
  }finally{
    if(!complete){try{Promise.resolve(reader.cancel()).catch(()=>{});}catch{}}
    reader.releaseLock();
  }
  const bytes=Buffer.concat(blocks,count),raw=bytes.toString('utf8');
  if(!Buffer.from(raw,'utf8').equals(bytes))
    deny('NATIVE_COMMENT_INVALID_ENCODING');
  try{return JSON.parse(raw);}catch{deny('NATIVE_COMMENT_INVALID_RESPONSE');}
}
/**
 * Cautious bridge to a REAL native COMMENTED GitHub App review.
 * It can NEVER publish APPROVED, CHANGES_REQUESTED or an attested PASS.
 * Explicit protected-runtime authorization must be derived ONLY from a
 * reviewed workflow and its approved GitHub environment.
 *
 * There is no standalone auto-retry; the eventual protected workflow must
 * use a fixed concurrency group for each exact PR to close check/POST race.
 */
export async function publishNonAuthorizingNativeReview({
  privatePreflight,runId,expectedHeadSha,
  readToken,writeToken,approvedProtectedComment=false,
  fetchImpl=globalThis.fetch
}={}){
  if(approvedProtectedComment!==true)
    deny('NATIVE_COMMENT_NOT_AUTHORIZED');
  if(typeof fetchImpl!=='function'||
     typeof readToken!=='string'||readToken.length<15||readToken.length>2000||
     typeof writeToken!=='string'||writeToken.length<15||writeToken.length>2000||
     /[^-_A-Za-z0-9.]/.test(readToken)||
     /[^-_A-Za-z0-9.]/.test(writeToken)||readToken===writeToken)
    deny('NATIVE_COMMENT_INVALID_SCOPED_TOKENS');
  const plan=prepareNonAuthorizingNativeComment({
    privatePreflight,runId,expectedHeadSha
  });
  const read=()=>readNativeReviews({
    prNumber:plan.prNumber,expectedHeadSha:plan.headSha,
    installationToken:readToken,fetchImpl
  });
  const prior=await read();
  const uniqueness=assessNativeReviewUniqueness({
    observed:prior,prNumber:plan.prNumber,currentHeadSha:plan.headSha
  });
  if(uniqueness.blocked)deny('NATIVE_COMMENT_EXISTING_REVIEW_BLOCK');
  const url=`https://api.github.com/repos/${REPO}/pulls/${plan.prNumber}/reviews`;
  const reqBody=JSON.stringify({
    event:'COMMENT',commit_id:plan.headSha,body:plan.body
  });
  let response;
  try{
    response=await fetchImpl(url,{
      method:'POST',redirect:'error',cache:'no-store',
      signal:AbortSignal.timeout(15000),
      headers:{
        Authorization:`Bearer ${writeToken}`,
        Accept:'application/vnd.github+json',
        'Content-Type':'application/json',
        'X-GitHub-Api-Version':'2022-11-28',
        'User-Agent':'devfactory-reviewer-b-comment-only'
      },
      body:reqBody
    });
  }catch{deny('NATIVE_COMMENT_POST_FAILED');}
  if(response?.url!==url||response?.redirected!==false||
     ![200,201].includes(response?.status)||
     typeof response.headers?.get!=='function'||
     !/^application\/(?:vnd\.github\+)?json(?:\s*;|$)/i.test(
       response.headers.get('content-type')||''))deny('NATIVE_COMMENT_POST_REJECTED');
  const length=response.headers.get('content-length');
  if(length!==null&&length!==undefined&&length!==''&&
     (!/^\d+$/.test(length)||Number(length)>RESP_LIMIT))
    deny('NATIVE_COMMENT_POST_RESPONSE_OVERSIZED');
  let created;
  try{created=await boundedResponse(response);}
  catch{deny('NATIVE_COMMENT_POST_RESPONSE_INVALID');}
  if(!created||!Number.isSafeInteger(created.id)||created.id<1||
     created.state!=='COMMENTED'||created.commit_id!==plan.headSha||
     created.user?.id!==BOT_ID||created.user?.login!==BOT_LOGIN||
     created.pull_request_url!==
       `https://api.github.com/repos/${REPO}/pulls/${plan.prNumber}`||
     typeof created.body!=='string'||created.body!==plan.body)
    deny('NATIVE_COMMENT_POST_IDENTITY_UNVERIFIED');
  const after=await read();
  const observed=after.reviews.filter(x=>x.user.id===BOT_ID||
    x.user.login===BOT_LOGIN);
  const matches=observed.filter(x=>x.id===created.id&&
    x.commit_id===plan.headSha&&x.state==='COMMENTED'&&
    x.body===plan.body&&x.user.id===BOT_ID&&x.user.login===BOT_LOGIN);
  if(matches.length!==1||
     observed.filter(x=>x.commit_id===plan.headSha).length!==1)
    deny('NATIVE_COMMENT_READBACK_MISMATCH');
  return Object.freeze({
    nativeReviewId:created.id,prNumber:plan.prNumber,headSha:plan.headSha,
    evidenceClass:'NATIVE_COMMENT_ONLY',event:'COMMENTED',
    independentReviewVerified:false,approvalAuthorized:false,
    reviewerPass:false,attestedReportVerified:false,
    humanGoVerified:false
  });
}
