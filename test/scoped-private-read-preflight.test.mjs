import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash,generateKeyPairSync } from 'node:crypto';
import {inspect} from 'node:util';
import {runScopedPrivateReadPreflight}
  from '../candidate/scoped-private-read-preflight.mjs';
const now=Date.parse('2026-10-11T12:00:00Z');
const key=generateKeyPairSync('rsa',{modulusLength:2048})
  .privateKey.export({type:'pkcs8',format:'pem'});
const TOKEN='ghs_SYNTHETIC_BOUNDED_READ_ONLY_TOKEN_123';
const APP='https://api.github.com/app/installations/169674558/access_tokens';
const PR='https://api.github.com/repos/deenkids7-dev/deenkids/pulls/898';
const DIFF_URL='https://api.github.com/repos/deenkids7-dev/deenkids/compare/'
  +'b'.repeat(40)+'...'+'a'.repeat(40);
const privateText='SYNTHETIC_SENSITIVE_NOT_REAL_PRIVATE_CODE';
const diff=Buffer.from('diff --git a/demo.mjs b/demo.mjs\n'+
 'index aaaa..bbbb 100644\n--- a/demo.mjs\n+++ b/demo.mjs\n'+
 '@@ -1 +1 @@\n-old\n+safe_'+privateText+'\n');
const meta=()=>({number:898,state:'open',merged_at:null,draft:false,
 changed_files:1,head:{sha:'a'.repeat(40),repo:{
 full_name:'deenkids7-dev/deenkids',id:1282086207}},
 base:{sha:'b'.repeat(40),ref:'master',repo:{
 full_name:'deenkids7-dev/deenkids',id:1282086207}}});
const response=(url,status,type,body)=>{
 const bytes=Buffer.isBuffer(body)?body:Buffer.from(JSON.stringify(body));
 return {url,status,redirected:false,
  headers:new Headers({'content-type':type,'content-length':String(bytes.length)}),
  body:new ReadableStream({start(c){c.enqueue(new Uint8Array(bytes));c.close();}})
 };
};
function service(overrides={}){
 const calls=[];
 const fetchImpl=async(url,req)=>{
  calls.push({url,method:req.method,body:req.body,
   authorization:req.headers.Authorization,accept:req.headers.Accept});
  if(url===APP){
   const permissions=overrides.permissions||
     {pull_requests:'read',contents:'read',metadata:'read'};
   return response(url,201,'application/json',{
    token:TOKEN,
    expires_at:new Date(now+55*60000).toISOString().replace('.000Z','Z'),
    repository_selection:'selected',
    repositories:[{id:1282086207,full_name:'deenkids7-dev/deenkids'}],
    permissions
   });
  }
  if(overrides.error)throw Error('Private API returned '+TOKEN);
  const count=calls.filter(x=>x.url===PR).length;
  if(url===PR)return response(url,200,'application/json',
   count===2?(overrides.after||meta()):meta());
  if(url===DIFF_URL)return response(url,200,'text/plain; charset=utf-8',diff);
  throw Error('OUT_OF_SCOPE_TEST_CALL');
 };
 return {calls,fetchImpl};
}
const input=(fetchImpl)=>({
 prNumber:898,runId:'test-synthetic-read-898',appPrivateKeyPem:key,now,fetchImpl
});
test('JWT to downscoped installation token to immutable private read (synthetic)',async()=>{
 const mock=service();
 const output=await runScopedPrivateReadPreflight(input(mock.fetchImpl));
 assert.deepEqual(mock.calls.map(x=>x.url),[APP,PR,DIFF_URL,PR]);
 assert.equal(mock.calls[0].method,'POST');
 assert.deepEqual(JSON.parse(mock.calls[0].body),{
   repository_ids:[1282086207],
   permissions:{pull_requests:'read',contents:'read'}
 });
 assert.equal(mock.calls[1].authorization,'Bearer '+TOKEN);
 assert.ok(mock.calls.every(x=>x.method==='GET'||x.method==='POST'));
 assert.equal(output.target.diffSha256,
   createHash('sha256').update(diff).digest('hex'));
 assert.equal(output.staticDisposition,'INCONCLUSIVE');
 assert.equal(output.approvalAuthorized,false);
 assert.equal(output.publishEvent,null);
 assert.equal(output.independentReviewVerified,false);
 for(const value of [JSON.stringify(output),JSON.stringify({...output}),inspect(output)]){
   assert.ok(!value.includes(TOKEN));
   assert.ok(!value.includes(privateText));
   assert.ok(!value.includes('PRIVATE KEY'));
 }
});
test('wrong token permissions fail closed before any PRIVATE read',async()=>{
 const mock=service({permissions:{
   pull_requests:'write',contents:'read',metadata:'read'
 }});
 await assert.rejects(()=>runScopedPrivateReadPreflight(input(mock.fetchImpl)),
   /APP_AUTH_INSTALLATION_SCOPE_UNVERIFIED/);
 assert.equal(mock.calls.length,1);
});
test('private HEAD drift is rejected, no publishing is possible',async()=>{
 const mock=service({after:{...meta(),
   head:{...meta().head,sha:'c'.repeat(40)}}});
 await assert.rejects(()=>runScopedPrivateReadPreflight(input(mock.fetchImpl)),
   /GITHUB_PR_CHANGED_DURING_READ/);
 assert.equal(mock.calls.length,4);
});
test('API exception never reports token or private key',async()=>{
 const mock=service({error:true});
 await assert.rejects(()=>runScopedPrivateReadPreflight(input(mock.fetchImpl)),
   err=>!err.message.includes(TOKEN)&&!err.message.includes('PRIVATE KEY'));
});
test('malformed selectors deny before JWT or any network call',async()=>{
 const mock=service();
 for(const bad of [0,'898',[],null,-1,1.5]){
   await assert.rejects(()=>runScopedPrivateReadPreflight({
     ...input(mock.fetchImpl),prNumber:bad
   }),/PROTECTED_PREFLIGHT_INVALID_INPUT/);
 }
 assert.equal(mock.calls.length,0);
});
test('no private App PEM cannot generate an installation token',async()=>{
 const mock=service();
 await assert.rejects(()=>runScopedPrivateReadPreflight({
   ...input(mock.fetchImpl),appPrivateKeyPem:''
 }),/PROTECTED_PREFLIGHT_INVALID_INPUT/);
 assert.equal(mock.calls.length,0);
});
