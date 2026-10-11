import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { createHash, generateKeyPairSync, verify } from 'node:crypto';
import { createReviewerBAppJwt, createScopedReviewerBInstallationToken } from
  '../candidate/github-app-auth.mjs';

const pair=generateKeyPairSync('rsa',{modulusLength:2048});
const key=pair.privateKey.export({type:'pkcs8',format:'pem'});
const now=Date.parse('2026-10-10T12:00:00Z');
const TOKEN='ghs_FAKE_ONLY_THIS_IS_NOT_A_REAL_SECRET';
const API='https://api.github.com/app/installations/169674558/access_tokens';
const exp=new Date(now+55*60000).toISOString().replace('.000Z','Z');
function validResponse(overrides={}){
  const object={
    token:TOKEN,expires_at:exp,repository_selection:'selected',
    repositories:[{id:1282086207,full_name:'deenkids7-dev/deenkids'}],
    permissions:{pull_requests:'write',metadata:'read'},...overrides
  };
  const bytes=Buffer.from(JSON.stringify(object));
  return {
    url:API,status:201,redirected:false,
    headers:new Headers({'content-type':'application/json'}),
    body:new ReadableStream({start(controller){controller.enqueue(bytes);controller.close();}})
  };
}
function fakeTransport(options={}) {
  const calls=[];
  const fetchImpl=async (url,config)=>{
    calls.push({url,config});
    if(options.error)throw new Error('KEY LEAK: '+TOKEN);
    const result=validResponse(options.body||{});
    if(options.status)result.status=options.status;
    if(options.url)result.url=options.url;
    if(options.redirected)result.redirected=true;
    return result;
  };
  return {fetchImpl,calls};
}

test('test-only GitHub App RSA JWT has strict app identity and verified signature',()=>{
  const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
  const [h,p,s]=jwt.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(h,'base64url')),{
    alg:'RS256',typ:'JWT'
  });
  const payload=JSON.parse(Buffer.from(p,'base64url'));
  assert.deepEqual(payload,{
    iat:Math.floor(now/1000)-60,exp:Math.floor(now/1000)+480,
    iss:'5253138'
  });
  assert.ok(verify('RSA-SHA256',Buffer.from(h+'.'+p),
    pair.publicKey,Buffer.from(s,'base64url')));
  assert.equal(jwt.includes('PRIVATE KEY'),false);
});

test('JWT rejects keys not suitable for GitHub App RSA signing',()=>{
  const ed=generateKeyPairSync('ed25519');
  for(const candidate of [null,'', 'invalid',ed.privateKey.export({
    type:'pkcs8',format:'pem'
  })]){
    assert.throws(()=>createReviewerBAppJwt({
      privateKeyPem:candidate,now
    }),/(?:APP_AUTH_INVALID_(?:KEY_OR_CLOCK|RSA_PRIVATE_KEY)|APP_AUTH_KEY_TYPE_DENIED)/);
  }
});

test('scoped token request restricts exact installation and repository ID',async()=>{
  const mock=fakeTransport();
  const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
  const result=await createScopedReviewerBInstallationToken({
    appJwt:jwt,fetchImpl:mock.fetchImpl,now,purpose:'publish'
  });
  assert.equal(result.repositoryId,1282086207);
  assert.equal(result.installationId,169674558);
  assert.equal(result.token,TOKEN);
  assert.equal(mock.calls.length,1);
  const {url,config}=mock.calls[0];
  assert.equal(url,API);
  assert.equal(config.method,'POST');
  assert.equal(config.redirect,'error');
  assert.equal(config.headers.Authorization,'Bearer '+jwt);
  assert.deepEqual(JSON.parse(config.body),{
    repository_ids:[1282086207],permissions:{pull_requests:'write'}
  });
  assert.equal(JSON.stringify(result).includes(jwt),false);
});

test('token API errors never reveal private token or JWT',async()=>{
  const mock=fakeTransport({error:true});
  await assert.rejects(()=>createScopedReviewerBInstallationToken({
    appJwt:createReviewerBAppJwt({privateKeyPem:key,now}),
    fetchImpl:mock.fetchImpl,now,purpose:'publish'
  }),e=>e.message==='APP_AUTH_API_REQUEST_FAILED'&&!e.message.includes(TOKEN));
});
test('rejected oversized scoped-token response cancels stream without leaking credentials',async()=>{
  const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
  let cancelled=false,lockedReleased=false,readCount=0;
  const reader={
    async read(){
      readCount++;
      return {done:false,value:new Uint8Array(48*1024+1)};
    },
    async cancel(){cancelled=true;},
    releaseLock(){lockedReleased=true;}
  };
  const response={
    status:201,redirected:false,url:API,
    headers:new Headers({'content-type':'application/json'}),
    body:{getReader:()=>reader}
  };
  await assert.rejects(()=>createScopedReviewerBInstallationToken({
    appJwt:jwt,fetchImpl:async()=>response,now,purpose:'publish'
  }),e=>e.message==='APP_AUTH_BAD_RESPONSE'&&!e.message.includes(jwt));
  assert.equal(readCount,1);
  assert.equal(cancelled,true);
  assert.equal(lockedReleased,true);
});
test('scoped-token response cancellation failure cannot override fail-closed denial',async()=>{
  const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
  let released=false;
  const response={
    status:201,redirected:false,url:API,
    headers:new Headers({'content-type':'application/json'}),
    body:{getReader:()=>({
      async read(){return {done:false,value:new Uint8Array(48*1024+1)};},
      async cancel(){throw new Error('transport cancel failure');},
      releaseLock(){released=true;}
    })}
  };
  await assert.rejects(()=>createScopedReviewerBInstallationToken({
    appJwt:jwt,fetchImpl:async()=>response,now,purpose:'publish'
  }),e=>e.message==='APP_AUTH_BAD_RESPONSE');
  assert.equal(released,true);
});
test('GitHub API responses must come from exact installation endpoint',async()=>{
  for(const options of [
    {url:'https://example.test/token'},
    {status:200}, {redirected:true}
  ]){
    const mock=fakeTransport(options);
    await assert.rejects(()=>createScopedReviewerBInstallationToken({
      appJwt:createReviewerBAppJwt({privateKeyPem:key,now}),
      fetchImpl:mock.fetchImpl,now,purpose:'publish'
    }),/APP_AUTH_API_RESPONSE_REJECTED/);
  }
});
test('installation tokens cannot silently expand repository or permissions',async()=>{
  for(const body of [
    {repositories:[{id:1,full_name:'other/repo'}]},
    {repositories:[{id:1282086207,full_name:'deenkids7-dev/deenkids'},
      {id:42,full_name:'other/repo'}]},
    {repository_selection:'all'},
    {permissions:{pull_requests:'read'}},
    {permissions:{pull_requests:'write',contents:'write'}},
    {permissions:{pull_requests:'write',administration:'write'}},
    {expires_at:'2026-10-10T12:00:10Z'},
    {token:'bad token\nHeader:evil'}
  ]){
    const mock=fakeTransport({body});
    await assert.rejects(()=>createScopedReviewerBInstallationToken({
      appJwt:createReviewerBAppJwt({privateKeyPem:key,now}),
      fetchImpl:mock.fetchImpl,now,purpose:'publish'
    }),/APP_AUTH_INSTALLATION_SCOPE_UNVERIFIED/);
  }
});
test('missing JWT never calls the network',async()=>{
  const mock=fakeTransport();
  await assert.rejects(()=>createScopedReviewerBInstallationToken({
    appJwt:'',fetchImpl:mock.fetchImpl,now,purpose:'publish'
  }),/APP_AUTH_INVALID_REQUEST/);
  assert.equal(mock.calls.length,0);
});

test('omitting token purpose cannot mint a write-scoped GitHub installation token',async()=>{
  const mock=fakeTransport();
  const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
  await assert.rejects(()=>createScopedReviewerBInstallationToken({
    appJwt:jwt,fetchImpl:mock.fetchImpl,now
  }),/APP_AUTH_INVALID_REQUEST/);
  assert.equal(mock.calls.length,0);
});

test('immutable private compare requires separate Contents:read GitHub App token',async()=>{
  const mock=fakeTransport({body:{
    permissions:{contents:'read',pull_requests:'read',metadata:'read'}
  }});
  const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
  const token=await createScopedReviewerBInstallationToken({
    appJwt:jwt,fetchImpl:mock.fetchImpl,now,purpose:'reviewRead'
  });
  assert.equal(token.purpose,'reviewRead');
  assert.equal(token.repositoryId,1282086207);
  assert.equal(token.token,TOKEN);
  assert.deepEqual(JSON.parse(mock.calls[0].config.body),{
    repository_ids:[1282086207],
    permissions:{pull_requests:'read',contents:'read'}
  });
});
test('separate read token cannot silently gain PR write or repository write',async()=>{
  const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
  for(const permissions of [
    {contents:'read',pull_requests:'write',metadata:'read'},
    {contents:'write',pull_requests:'read',metadata:'read'},
    {contents:'read',pull_requests:'read',issues:'write',metadata:'read'},
    {contents:'read',pull_requests:'read',administration:'read',metadata:'read'},
    {contents:'none',pull_requests:'read',metadata:'read'}
  ]){
    const mock=fakeTransport({body:{permissions}});
    await assert.rejects(()=>createScopedReviewerBInstallationToken({
      appJwt:jwt,fetchImpl:mock.fetchImpl,now,purpose:'reviewRead'
    }),e=>e.message==='APP_AUTH_INSTALLATION_SCOPE_UNVERIFIED');
  }
});
test('no unknown token purpose may be used to issue a GitHub credential',async()=>{
  const mock=fakeTransport();
  await assert.rejects(()=>createScopedReviewerBInstallationToken({
    appJwt:createReviewerBAppJwt({privateKeyPem:key,now}),
    fetchImpl:mock.fetchImpl,now,purpose:'issueWrite'
  }),e=>e.message==='APP_AUTH_INVALID_REQUEST');
  assert.equal(mock.calls.length,0);
});
test('publication token cannot receive Contents:read or Issues:read',async()=>{
  const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
  for(const permissions of [
    {pull_requests:'write',contents:'read',metadata:'read'},
    {pull_requests:'write',issues:'read',metadata:'read'}
  ]){
    const mock=fakeTransport({body:{permissions}});
    await assert.rejects(()=>createScopedReviewerBInstallationToken({
      appJwt:jwt,fetchImpl:mock.fetchImpl,now,purpose:'publish'
    }),e=>e.message==='APP_AUTH_INSTALLATION_SCOPE_UNVERIFIED');
  }
});

test('future canonical HUMAN_GO reader can request Issues:read ONLY',async()=>{
 const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
 const mock=fakeTransport({body:{
   permissions:{issues:'read',metadata:'read'}
 }});
 const token=await createScopedReviewerBInstallationToken({
   appJwt:jwt,fetchImpl:mock.fetchImpl,now,purpose:'humanGoRead'
 });
 assert.equal(token.purpose,'humanGoRead');
 assert.equal(token.repositoryId,1282086207);
 assert.deepEqual(JSON.parse(mock.calls[0].config.body),{
   repository_ids:[1282086207],permissions:{issues:'read'}
 });
});
test('HUMAN_GO token refuses escalation to PR write, Contents read or Issues write',async()=>{
 const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
 for(const permissions of [
   {issues:'read',pull_requests:'write',metadata:'read'},
   {issues:'read',contents:'read',metadata:'read'},
   {issues:'write',metadata:'read'},
   {issues:'read',administration:'read',metadata:'read'}
 ]){
   const mock=fakeTransport({body:{permissions}});
   await assert.rejects(()=>createScopedReviewerBInstallationToken({
     appJwt:jwt,fetchImpl:mock.fetchImpl,now,purpose:'humanGoRead'
   }),/APP_AUTH_INSTALLATION_SCOPE_UNVERIFIED/);
 }
});
test('a publish token cannot silently gain HUMAN_GO Issues read',async()=>{
 const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
 const mock=fakeTransport({body:{
   permissions:{pull_requests:'write',issues:'read',metadata:'read'}
 }});
 await assert.rejects(()=>createScopedReviewerBInstallationToken({
   appJwt:jwt,fetchImpl:mock.fetchImpl,now,purpose:'publish'
 }),/APP_AUTH_INSTALLATION_SCOPE_UNVERIFIED/);
});

test('scoped GitHub App installation token cannot leak from ordinary object logging',async()=>{
 const f=fakeTransport();
 const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
 const result=await createScopedReviewerBInstallationToken({
  appJwt:jwt,fetchImpl:f.fetchImpl,now,purpose:'publish'
 });
 assert.equal(result.token,TOKEN);
 assert.equal(Object.keys(result).includes('token'),false);
 for(const str of [JSON.stringify(result),JSON.stringify({...result}),inspect(result)]){
  assert.ok(!str.includes(TOKEN));
  assert.ok(!str.includes(jwt));
 }
 assert.match(JSON.stringify(result),/REDACTED_INSTALLATION_TOKEN/);
 assert.equal(result.purpose,'publish');
 assert.equal(Object.isFrozen(result),true);
});
test('wrong-type and weak RSA App keys preserve precise key-type denial',()=>{
  const ed=generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'});
  const weak=generateKeyPairSync('rsa',{modulusLength:1024}).privateKey.export({type:'pkcs8',format:'pem'});
  for(const privateKeyPem of [ed,weak]){
    assert.throws(()=>createReviewerBAppJwt({privateKeyPem,now}),
      e=>e.message==='APP_AUTH_KEY_TYPE_DENIED');
  }
  assert.throws(()=>createReviewerBAppJwt({privateKeyPem:'not-a-key'.repeat(12),now}),
    e=>e.message==='APP_AUTH_INVALID_RSA_PRIVATE_KEY');
});
