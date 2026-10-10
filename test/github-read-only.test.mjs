import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadOnlyGitHubTransport, readCurrentGitHubPrSnapshot }
  from '../candidate/github-read-only.mjs';

const TOKEN='ghs_SYNTHETIC_NOT_A_REAL_TOKEN';
const URL='https://api.github.com/repos/deenkids7-dev/deenkids/pulls/898';
const digest=b=>createHash('sha256').update(b).digest('hex');
const DIFF=Buffer.from(
  'diff --git a/demo.mjs b/demo.mjs\nindex abcd111..1234abc 100644\n' +
  '--- a/demo.mjs\n+++ b/demo.mjs\n@@ -1 +1 @@\n-before\n+after\n');
const metadata=()=>({
  number:898,state:'open',merged_at:null,draft:false,changed_files:1,
  head:{sha:'a'.repeat(40),repo:{full_name:'deenkids7-dev/deenkids',id:1282086207}},base:{sha:'b'.repeat(40),ref:'master',
    repo:{full_name:'deenkids7-dev/deenkids',id:1282086207}}
});
function response(url,body,type,status=200,options={}) {
  const bytes=Buffer.isBuffer(body)?body:Buffer.from(JSON.stringify(body));
  return {
    url,status,redirected:options.redirected||false,
    headers:new Headers({'content-type':type,
      'content-length':String(options.claimedLength??bytes.length)}),
    body:new ReadableStream({start(controller){
      controller.enqueue(new Uint8Array(bytes));controller.close();
    }})
  };
}
function fakeGitHub(options={}) {
  const calls=[];
  const fetchImpl=async (url,req)=>{
    calls.push({url,method:req.method,redirect:req.redirect,
      accept:req.headers.Accept,authorization:req.headers.Authorization,
      apiVersion:req.headers['X-GitHub-Api-Version']});
    const n=calls.length;
    const isDiff=req.headers.Accept==='application/vnd.github.diff';
    const data=isDiff?(options.diff||DIFF):
      n===3?(options.after||metadata()):(options.before||metadata());
    const type=options.contentType||(isDiff?'text/plain; charset=utf-8':'application/json; charset=utf-8');
    const result=response(url,data,type,options.status||200,options);
    if(options.redirectTarget)result.url=options.redirectTarget;
    if(options.abort)throw new Error('private service failure secret='+TOKEN);
    return result;
  };
  return {fetchImpl,calls};
}
test('real transport shape reads exact PR twice and raw diff once; no writes',async()=>{
  const fake=fakeGitHub();
  const snapshot=await readCurrentGitHubPrSnapshot({
    prNumber:898,installationToken:TOKEN,fetchImpl:fake.fetchImpl
  });
  assert.equal(snapshot.pr_number,898);
  assert.equal(snapshot.diff_sha256,digest(DIFF));
  assert.equal(snapshot.head_sha,'a'.repeat(40));
  assert.equal(fake.calls.length,3);
  assert.deepEqual(fake.calls.map(x=>x.accept),
    ['application/vnd.github+json','application/vnd.github.diff',
     'application/vnd.github+json']);
  for(const c of fake.calls){
    assert.equal(c.url,URL);
    assert.equal(c.method,'GET');
    assert.equal(c.redirect,'error');
    assert.equal(c.authorization,`Bearer ${TOKEN}`);
  }
  assert.equal(JSON.stringify(snapshot).includes(TOKEN),false);
  assert.ok(Object.isFrozen(snapshot));
});
test('private token never appears in network exception',async()=>{
  const {fetchImpl}=fakeGitHub({abort:true});
  await assert.rejects(()=>readCurrentGitHubPrSnapshot({
    prNumber:898,installationToken:TOKEN,fetchImpl
  }),e=>e.message==='GITHUB_REQUEST_FAILED'&&!e.message.includes(TOKEN));
});
test('PR HEAD moving between reads is rejected',async()=>{
  const fake=fakeGitHub({after:{...metadata(),head:{...metadata().head,sha:'c'.repeat(40)}}});
  await assert.rejects(()=>readCurrentGitHubPrSnapshot({
    prNumber:898,installationToken:TOKEN,fetchImpl:fake.fetchImpl
  }),/GITHUB_PR_CHANGED_DURING_READ/);
});
test('untrusted repository ID never accepted',async()=>{
  const fake=fakeGitHub({before:{...metadata(),base:{...metadata().base,
    repo:{full_name:'deenkids7-dev/deenkids',id:42}}}});
  await assert.rejects(()=>readCurrentGitHubPrSnapshot({
    prNumber:898,installationToken:TOKEN,fetchImpl:fake.fetchImpl
  }),/GITHUB_PR_NOT_ELIGIBLE/);
});
test('stale or draft PR cannot be treated as valid',async()=>{
  const fake=fakeGitHub({before:{...metadata(),draft:true}});
  await assert.rejects(()=>readCurrentGitHubPrSnapshot({
    prNumber:898,installationToken:TOKEN,fetchImpl:fake.fetchImpl
  }),/GITHUB_PR_NOT_ELIGIBLE/);
});
test('PR selector rejects untrusted path injection',async()=>{
  const fake=fakeGitHub();
  for(const prNumber of ['898','../secret',0,-1,1.5,2147483648]){
    await assert.rejects(()=>readCurrentGitHubPrSnapshot({
      prNumber,installationToken:TOKEN,fetchImpl:fake.fetchImpl
    }),/INVALID_PR_SELECTOR/);
  }
  assert.equal(fake.calls.length,0);
});
test('transport forbids alternate endpoint, non-GET and unapproved Accept',async()=>{
  const fake=fakeGitHub();
  const get=createReadOnlyGitHubTransport({
    installationToken:TOKEN,fetchImpl:fake.fetchImpl});
  const valid={url:URL,method:'GET',
    accept:'application/vnd.github+json',maxBytes:1024};
  for(const x of [
    {...valid,url:'https://github.example/repos/deenkids7-dev/deenkids/pulls/898'},
    {...valid,url:'https://api.github.com/repos/other/private/pulls/898'},
    {...valid,url:URL+'/reviews'},
    {...valid,method:'POST'},
    {...valid,accept:'application/octet-stream'},
    {...valid,maxBytes:10000000}
  ]) await assert.rejects(()=>get(x),/GITHUB_(?:ENDPOINT_DENIED|READ_CONTRACT_VIOLATION)/);
  assert.equal(fake.calls.length,0);
});
test('redirected responses cannot move authorization header',async()=>{
  const fake=fakeGitHub({redirectTarget:'https://attacker.example/capture'});
  const get=createReadOnlyGitHubTransport({
    installationToken:TOKEN,fetchImpl:fake.fetchImpl});
  await assert.rejects(()=>get({url:URL,method:'GET',
    accept:'application/vnd.github+json',maxBytes:1024}),
    /GITHUB_NONCANONICAL_RESPONSE/);
  assert.equal(fake.calls[0].redirect,'error');
});
test('untrusted response type, non-200 and oversize are blocked',async()=>{
  for(const options of [
    {status:206}, {contentType:'text/html'},
    {claimedLength:3*1024*1024},
    {diff:Buffer.alloc(2*1024*1024+1,0x41)}
  ]) {
    const fake=fakeGitHub(options);
    await assert.rejects(()=>readCurrentGitHubPrSnapshot({
      prNumber:898,installationToken:TOKEN,fetchImpl:fake.fetchImpl
    }));
  }
});
test('no token, invalid token or untrusted client is rejected',()=>{
  for(const installationToken of [null,'','123','bad token\nX:evil']){
    assert.throws(()=>createReadOnlyGitHubTransport({
      installationToken,fetchImpl:async()=>{throw Error('should never run')}
    }),/INVALID_INSTALLATION_TOKEN/);
  }
});
