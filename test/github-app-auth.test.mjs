import test from 'node:test';
import assert from 'node:assert/strict';
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
    }),/APP_AUTH_INVALID_(?:KEY_OR_CLOCK|RSA_PRIVATE_KEY)/);
  }
});

test('scoped token request restricts exact installation and repository ID',async()=>{
  const mock=fakeTransport();
  const jwt=createReviewerBAppJwt({privateKeyPem:key,now});
  const result=await createScopedReviewerBInstallationToken({
    appJwt:jwt,fetchImpl:mock.fetchImpl,now
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
    fetchImpl:mock.fetchImpl,now
  }),e=>e.message==='APP_AUTH_API_REQUEST_FAILED'&&!e.message.includes(TOKEN));
});
test('GitHub API responses must come from exact installation endpoint',async()=>{
  for(const options of [
    {url:'https://example.test/token'},
    {status:200}, {redirected:true}
  ]){
    const mock=fakeTransport(options);
    await assert.rejects(()=>createScopedReviewerBInstallationToken({
      appJwt:createReviewerBAppJwt({privateKeyPem:key,now}),
      fetchImpl:mock.fetchImpl,now
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
      fetchImpl:mock.fetchImpl,now
    }),/APP_AUTH_INSTALLATION_SCOPE_UNVERIFIED/);
  }
});
test('missing JWT never calls the network',async()=>{
  const mock=fakeTransport();
  await assert.rejects(()=>createScopedReviewerBInstallationToken({
    appJwt:'',fetchImpl:mock.fetchImpl,now
  }),/APP_AUTH_INVALID_REQUEST/);
  assert.equal(mock.calls.length,0);
});
