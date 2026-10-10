import { inspect } from 'node:util';
// Read-only native GitHub review observation. No approval or review POST.
const REPO='deenkids7-dev/deenkids';
const PREFIX=`https://api.github.com/repos/${REPO}/pulls/`;
const MAX_PAGE_BYTES=1024*1024;
const MAX_REVIEWS=250;
const REPO_ID=1282086207;
const METADATA_MAX=512*1024;
const SHA40=/^[0-9a-f]{40}$/;
function deny(code){throw new Error(code);}
async function readBounded(body,maxBytes=MAX_PAGE_BYTES){
  if(!body?.getReader)deny('REVIEWS_UNREADABLE_BODY');
  const reader=body.getReader();let size=0;const items=[];
  try{
    for(;;){
      const {done,value}=await reader.read();
      if(done)break;
      if(!(value instanceof Uint8Array))deny('REVIEWS_INVALID_CHUNK');
      size+=value.length;
      if(size>maxBytes)deny('REVIEWS_OVERSIZED_PAGE');
      items.push(Buffer.from(value));
    }
  }finally{reader.releaseLock();}
  return Buffer.concat(items,size);
}
async function observedHead({prNumber,installationToken,fetchImpl}) {
  const url=`${PREFIX}${prNumber}`;
  let response;
  try {
    response=await fetchImpl(url,{
      method:'GET',redirect:'error',cache:'no-store',
      signal:AbortSignal.timeout(15000),
      headers:{
        Authorization:`Bearer ${installationToken}`,
        Accept:'application/vnd.github+json',
        'X-GitHub-Api-Version':'2022-11-28',
        'User-Agent':'devfactory-native-review-readback'
      }
    });
  }catch{deny('REVIEWS_HEAD_READ_FAILED');}
  if(response?.url!==url||response?.status!==200||
     response?.redirected!==false||
     !/^application\/(?:vnd\.github\+)?json(?:\s*;|$)/i.test(
       response.headers?.get('content-type')||''))deny('REVIEWS_HEAD_UNTRUSTED');
  const headerSize=response.headers?.get('content-length');
  if(headerSize && (!/^\d+$/.test(headerSize) || Number(headerSize)>METADATA_MAX))
    deny('REVIEWS_HEAD_OVERSIZED');
  let pr;
  try {
    const bytes=await readBounded(response.body,METADATA_MAX);
    const raw=bytes.toString('utf8');
    if(!Buffer.from(raw,'utf8').equals(bytes))deny('INVALID_ENCODING');
    pr=JSON.parse(raw);
  }catch{deny('REVIEWS_HEAD_INVALID_JSON');}
  if(pr?.number!==prNumber||pr?.state!=='open'||pr?.merged_at!==null||
     pr?.head?.repo?.id!==REPO_ID||pr?.head?.repo?.full_name!==REPO||
     pr?.base?.repo?.id!==REPO_ID||pr?.base?.repo?.full_name!==REPO||
     typeof pr.head.sha!=='string'||!SHA40.test(pr.head.sha)) {
    deny('REVIEWS_HEAD_UNTRUSTED');
  }
  return pr.head.sha;
}

/**
 * Reviews must come from the separately authenticated GitHub App installation,
 * not from the PR body. This only reads and structurally bounds responses.
 * Caller must use PR #900's separate signature + independent provenance
 * verifier before EVER treating any review as trusted.
 */
export async function readNativeReviews({
  prNumber,expectedHeadSha,installationToken,fetchImpl=fetch
}={}){
  if(!Number.isSafeInteger(prNumber)||prNumber<1||prNumber>2147483647||
     typeof expectedHeadSha!=='string'||!SHA40.test(expectedHeadSha)||
     typeof installationToken!=='string'||installationToken.length<15||
     installationToken.length>2000||
     /[^A-Za-z0-9_\-.]/.test(installationToken)||
     typeof fetchImpl!=='function')deny('REVIEWS_INVALID_REQUEST');
  const beforeHead=await observedHead({prNumber,installationToken,fetchImpl});
  if(beforeHead!==expectedHeadSha)deny('REVIEWS_HEAD_CHANGED_OR_UNVERIFIED');
  const result=[];const seen=new Set();
  for(let page=1;page<=3;page++){
    const url=`${PREFIX}${prNumber}/reviews?per_page=100&page=${page}`;
    let response;
    try{
      response=await fetchImpl(url,{
        method:'GET',redirect:'error',cache:'no-store',
        signal:AbortSignal.timeout(15000),
        headers:{
          Authorization:`Bearer ${installationToken}`,
          Accept:'application/vnd.github+json',
          'X-GitHub-Api-Version':'2022-11-28',
          'User-Agent':'devfactory-native-review-readback'
        }
      });
    }catch{deny('REVIEWS_GITHUB_REQUEST_FAILED');}
    if(response?.url!==url || response?.status!==200 ||
       response?.redirected!==false||
       !/^application\/(?:vnd\.github\+)?json(?:\s*;|$)/i.test(
         response.headers?.get('content-type')||'')){
      deny('REVIEWS_GITHUB_RESPONSE_REJECTED');
    }
    let pageData;
    try{
      const bytes=await readBounded(response.body);
      const raw=bytes.toString('utf8');
      if(!Buffer.from(raw,'utf8').equals(bytes))
        deny('REVIEWS_GITHUB_INVALID_UTF8');
      pageData=JSON.parse(raw);
    }catch{deny('REVIEWS_GITHUB_MALFORMED_JSON');}
    if(!Array.isArray(pageData)||pageData.length>100)
      deny('REVIEWS_PAGE_INVALID');
    for(const review of pageData){
      if(!review||!Number.isSafeInteger(review.id)||review.id<=0||
         seen.has(review.id)||
         !review.user||!Number.isSafeInteger(review.user.id)||
         typeof review.user.login!=='string'||
         !['APPROVED','CHANGES_REQUESTED','COMMENTED','DISMISSED','PENDING'].includes(review.state)||
         typeof review.commit_id!=='string'||!SHA40.test(review.commit_id)||
         (review.body!==null&&typeof review.body!=='string')||
         (typeof review.body==='string'&&review.body.length>120000)||
         review.pull_request_url!==`https://api.github.com/repos/${REPO}/pulls/${prNumber}`){
        deny('REVIEWS_ITEM_UNTRUSTED');
      }
      // Other commits are included for a downstream independent consumer;
      // they cannot be counted as reviews of expectedHeadSha.
      seen.add(review.id);
      // Copy only trusted schema fields. No mutable nested GitHub response
      // object is exposed to a later provenance/signature verifier.
      result.push(Object.freeze({
        id:review.id,
        user:Object.freeze({id:review.user.id,login:review.user.login}),
        commit_id:review.commit_id,state:review.state,body:review.body??'',
        submitted_at:review.submitted_at||null,
        pull_request_url:review.pull_request_url
      }));
      if(result.length>MAX_REVIEWS)deny('REVIEWS_TOO_MANY');
    }
    if(pageData.length<100){
      const afterHead=await observedHead({prNumber,installationToken,fetchImpl});
      if(afterHead!==beforeHead || afterHead!==expectedHeadSha)
        deny('REVIEWS_HEAD_CHANGED_OR_UNVERIFIED');
      // Review bodies can include PRIVATE repository findings and locations.
      // Preserve explicit access for the protected signature consumer only.
      const hiddenReviews=Object.freeze(result);
      const safe={
        targetHeadSha:afterHead,
        // No inference about signer provenance or release authority.
        independentReviewVerified:false,approvalAuthorized:false
      };
      Object.defineProperties(safe,{
        reviews:{enumerable:false,configurable:false,
          get:()=>hiddenReviews},
        toJSON:{enumerable:false,configurable:false,
          value:()=>({...Object.fromEntries(Object.entries(safe)),
            reviews:'[REDACTED_PRIVATE_REVIEWS]'})},
        [inspect.custom]:{enumerable:false,configurable:false,
          value:()=> '[ReadNativeReviews: PRIVATE REVIEW BODIES REDACTED]'
        }
      });
      return Object.freeze(safe);
    }
  }
  // A full 3rd page is at least 300 reviews; fail closed rather than truncate.
  deny('REVIEWS_TOO_MANY');
}
