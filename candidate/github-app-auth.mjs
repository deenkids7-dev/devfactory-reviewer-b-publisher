import { createPrivateKey, sign as rsaSign } from 'node:crypto';
import { inspect } from 'node:util';

// This is deliberately a dormant credential module: NOT loaded by public CI,
// NOT called by workflow, NOT an independent reviewer, and NO publishing path.
const APP_ID=5253138;
const INSTALLATION_ID=169674558;
const REPO_ID=1282086207;
const API='https://api.github.com';
const TOKEN_URL=`${API}/app/installations/${INSTALLATION_ID}/access_tokens`;
const PERMISSIONS=Object.freeze({
  publish:Object.freeze({pull_requests:'write'}),
  reviewRead:Object.freeze({pull_requests:'read',contents:'read'}),
  humanGoRead:Object.freeze({issues:'read'})
});
const MAX_RESPONSE=48*1024;

function deny(code) { throw new Error(code); }
function b64(value) {return Buffer.from(value).toString('base64url');}
function asUtc(value) {
  return typeof value==='string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value) &&
    Number.isFinite(Date.parse(value));
}
async function readResponse(response) {
  if (!response?.body?.getReader) deny('APP_AUTH_RESPONSE_UNREADABLE');
  const reader=response.body.getReader();
  const parts=[];let length=0;
  try {
    for (;;) {
      const {done,value}=await reader.read();
      if(done)break;
      if(!(value instanceof Uint8Array))deny('APP_AUTH_RESPONSE_UNREADABLE');
      length+=value.byteLength;
      if(length>MAX_RESPONSE)deny('APP_AUTH_RESPONSE_OVERSIZED');
      parts.push(Buffer.from(value));
    }
  } finally {reader.releaseLock();}
  return Buffer.concat(parts,length);
}

/**
 * JWT maker for the previously configured DevFactory Reviewer B GitHub App.
 * Private key is injected ONLY from a protected secret-bearing runtime.
 * Never persist it to disk, echo it or share with a public test workflow.
 * An RSA key here is for APP JWT ONLY, never for Reviewer B native RSA marker.
 */
export function createReviewerBAppJwt({privateKeyPem,now=Date.now()}={}) {
  if(typeof privateKeyPem!=='string' || privateKeyPem.length<100 ||
      privateKeyPem.length>16000 || !Number.isFinite(now) || now<0)
      deny('APP_AUTH_INVALID_KEY_OR_CLOCK');
  let key;
  try{
    key=createPrivateKey(privateKeyPem);
  }catch{deny('APP_AUTH_INVALID_RSA_PRIVATE_KEY');}
  if(key.asymmetricKeyType!=='rsa'||
     (key.asymmetricKeyDetails?.modulusLength||0)<2048)
    deny('APP_AUTH_KEY_TYPE_DENIED');
  const seconds=Math.floor(now/1000);
  const header=b64(JSON.stringify({alg:'RS256',typ:'JWT'}));
  const payload=b64(JSON.stringify({
    iat:seconds-60,exp:seconds+8*60,iss:String(APP_ID)
  }));
  const message=`${header}.${payload}`;
  const sig=rsaSign('RSA-SHA256',Buffer.from(message),key).toString('base64url');
  return `${message}.${sig}`;
}

/**
 * Only creates a one-hour (or shorter) installation token bound to exact
 * repository ID and an explicitly requested, downscoped PURPOSE.
 * 'publish': Pull requests:write, no Contents access.
 * 'reviewRead': Pull requests:read + Contents:read for immutable compare diff.
 * 'humanGoRead': Issues:read ONLY, pending explicit operator permission
 * change. Never grants Issues:write or reuses the publish token.
 * Does not review/approve/merge PRs.
 * This function is NOT allowed inside untrusted PR CI or on the MSI.
 * A fetchImpl override exists only for synthetic tests.
 */
export async function createScopedReviewerBInstallationToken({
  appJwt,fetchImpl=fetch,now=Date.now(),purpose
}={}) {
  if(typeof appJwt!=='string'||!/^[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+$/.test(appJwt)||
     appJwt.length>6000||!Number.isFinite(now)||typeof fetchImpl!=='function'||
     !Object.hasOwn(PERMISSIONS,purpose))
    deny('APP_AUTH_INVALID_REQUEST');
  let response;
  try{
    response=await fetchImpl(TOKEN_URL,{
      method:'POST',redirect:'error',cache:'no-store',
      signal:AbortSignal.timeout(15000),
      headers:{
        Authorization:`Bearer ${appJwt}`,Accept:'application/vnd.github+json',
        'Content-Type':'application/json',
        'X-GitHub-Api-Version':'2022-11-28',
        'User-Agent':'devfactory-reviewer-b-scoped-auth'
      },
      body:JSON.stringify({
        repository_ids:[REPO_ID],permissions:PERMISSIONS[purpose]
      })
    });
  }catch{deny('APP_AUTH_API_REQUEST_FAILED');}
  if(response?.status!==201||response?.redirected!==false||
     response?.url!==TOKEN_URL||
     !/^application\/(?:vnd\.github\+)?json(?:\s*;|$)/i.test(
       response.headers?.get('content-type')||'')){
    deny('APP_AUTH_API_RESPONSE_REJECTED');
  }
  let parsed;
  try{
    const bytes=await readResponse(response);
    const raw=bytes.toString('utf8');
    if(!Buffer.from(raw,'utf8').equals(bytes))deny('APP_AUTH_INVALID_UTF8');
    parsed=JSON.parse(raw);
  }catch{deny('APP_AUTH_BAD_RESPONSE');}
  if(typeof parsed?.token!=='string'||parsed.token.length<15||
     /[^A-Za-z0-9_\-.]/.test(parsed.token)||
     !asUtc(parsed.expires_at)||
     Date.parse(parsed.expires_at)<=now+60000||
     Date.parse(parsed.expires_at)>now+61*60000||
     parsed.repository_selection!=='selected'||
     !Array.isArray(parsed.repositories)||parsed.repositories.length!==1||
     parsed.repositories[0]?.id!==REPO_ID||
     parsed.repositories[0]?.full_name!=='deenkids7-dev/deenkids'||
     !parsed.permissions || typeof parsed.permissions!=='object' ||
     Array.isArray(parsed.permissions) ||
     Object.entries(PERMISSIONS[purpose]).some(([name,permission])=>
       parsed.permissions[name]!==permission) ||
     Object.entries(parsed.permissions).some(([name,value])=>
       (name==='metadata'&&value==='read') ? false :
       PERMISSIONS[purpose][name]===value ? false : true)) {
    deny('APP_AUTH_INSTALLATION_SCOPE_UNVERIFIED');
  }
  // A short-lived GitHub App token is still SECRET even if its source is
  // correctly scoped; never expose it via JSON, spread or Node debug output.
  const privateToken=parsed.token;
  const safe={
    expiresAt:parsed.expires_at,
    repositoryId:REPO_ID,installationId:INSTALLATION_ID,
    purpose
  };
  Object.defineProperties(safe,{
    token:{enumerable:false,configurable:false,
      get:()=>privateToken},
    toJSON:{enumerable:false,configurable:false,
      value:()=>({...Object.fromEntries(Object.entries(safe)),
        token:'[REDACTED_INSTALLATION_TOKEN]'})},
    [inspect.custom]:{enumerable:false,configurable:false,
      value:()=> '[ScopedReviewerBInstallationToken: SECRET REDACTED]'
    }
  });
  return Object.freeze(safe);
}
